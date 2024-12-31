package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
)

var (
	transportInstance *Transport
	transportMutex    sync.Mutex
)

const (
	PathfinderM     = 128 // Maximum number of hops that Reticulum will transport a packet
	PathRequestTTL  = 300 // Time to live for path requests in seconds
	AnnounceTimeout = 15  // Timeout for announce responses in seconds

	// Link constants
	EstablishmentTimeoutPerHop = 6   // Timeout for link establishment per hop
	KeepaliveTimeoutFactor     = 4   // RTT timeout factor for link timeout
	StaleGrace                 = 2   // Grace period in seconds
	Keepalive                  = 360 // Interval for sending keep-alive packets
	StaleTime                  = 720 // Time after which link is considered stale

	// Resource strategies
	AcceptNone = 0
	AcceptAll  = 1
	AcceptApp  = 2

	// Resource status
	ResourceStatusPending   = 0x00
	ResourceStatusActive    = 0x01
	ResourceStatusComplete  = 0x02
	ResourceStatusFailed    = 0x03
	ResourceStatusCancelled = 0x04

	// Direction constants
	OUT = 0x02
	IN  = 0x01

	// Destination type constants
	SINGLE = 0x00
	GROUP  = 0x01
	PLAIN  = 0x02
)

type PathInfo struct {
	NextHop     []byte
	Interface   string
	Hops        uint8
	LastUpdated time.Time
}

type Transport struct {
	config           *common.ReticulumConfig
	interfaces       map[string]common.NetworkInterface
	paths            map[string]*common.Path
	announceHandlers []AnnounceHandler
	mutex            sync.RWMutex
	handlerLock      sync.RWMutex
	pathLock         sync.RWMutex
	links            map[string]*Link
}

func NewTransport(config *common.ReticulumConfig) (*Transport, error) {
	t := &Transport{
		config:     config,
		interfaces: make(map[string]common.NetworkInterface),
		paths:      make(map[string]*common.Path),
		links:      make(map[string]*Link),
	}

	transportMutex.Lock()
	transportInstance = t
	transportMutex.Unlock()

	return t, nil
}

// Add GetTransportInstance function
func GetTransportInstance() *Transport {
	transportMutex.Lock()
	defer transportMutex.Unlock()
	return transportInstance
}

// Update the interface methods
func (t *Transport) RegisterInterface(name string, iface common.NetworkInterface) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if _, exists := t.interfaces[name]; exists {
		return errors.New("interface already registered")
	}

	t.interfaces[name] = iface
	return nil
}

func (t *Transport) GetInterface(name string) (common.NetworkInterface, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	iface, exists := t.interfaces[name]
	if !exists {
		return nil, errors.New("interface not found")
	}

	return iface, nil
}

// Update the Close method
func (t *Transport) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, iface := range t.interfaces {
		iface.Detach()
	}

	return nil
}

type Link struct {
	mutex               sync.RWMutex
	destination         []byte
	establishedAt       time.Time
	lastInbound         time.Time
	lastOutbound        time.Time
	lastData            time.Time
	rtt                 time.Duration
	establishedCb       func()
	closedCb            func()
	packetCb            func([]byte, *packet.Packet)
	resourceCb          func(interface{}) bool
	resourceStrategy    int
	resourceStartedCb   func(interface{})
	resourceConcludedCb func(interface{})
	remoteIdentifiedCb  func(*Link, []byte)
	connectedCb         func()
	disconnectedCb      func()
	remoteIdentity      []byte
	physicalStats       bool
	staleTime           time.Duration
	staleGrace          time.Duration
}

type Destination struct {
	Identity  interface{}
	Direction int
	Type      int
	AppName   string
	Aspects   []string
}

func NewLink(dest []byte, establishedCallback func(), closedCallback func()) *Link {
	return &Link{
		destination:   dest,
		establishedAt: time.Now(),
		lastInbound:   time.Now(),
		lastOutbound:  time.Now(),
		lastData:      time.Now(),
		establishedCb: establishedCallback,
		closedCb:      closedCallback,
		staleTime:     time.Duration(StaleTime) * time.Second,
		staleGrace:    time.Duration(StaleGrace) * time.Second,
	}
}

// Link methods
func (l *Link) GetAge() time.Duration {
	return time.Since(l.establishedAt)
}

func (l *Link) NoInboundFor() time.Duration {
	return time.Since(l.lastInbound)
}

func (l *Link) NoOutboundFor() time.Duration {
	return time.Since(l.lastOutbound)
}

func (l *Link) NoDataFor() time.Duration {
	return time.Since(l.lastData)
}

func (l *Link) InactiveFor() time.Duration {
	inbound := l.NoInboundFor()
	outbound := l.NoOutboundFor()
	if inbound < outbound {
		return inbound
	}
	return outbound
}

func (l *Link) SetPacketCallback(cb func([]byte, *packet.Packet)) {
	l.packetCb = cb
}

func (l *Link) SetResourceCallback(cb func(interface{}) bool) {
	l.resourceCb = cb
}

func (l *Link) Teardown() {
	if l.disconnectedCb != nil {
		l.disconnectedCb()
	}
	if l.closedCb != nil {
		l.closedCb()
	}
}

func (l *Link) Send(data []byte) error {
	l.lastOutbound = time.Now()
	l.lastData = time.Now()

	packet := &LinkPacket{
		Destination: l.destination,
		Data:        data,
		Timestamp:   time.Now(),
	}

	if l.rtt == 0 {
		l.rtt = l.InactiveFor()
	}

	return packet.send()
}

type AnnounceHandler interface {
	AspectFilter() []string
	ReceivedAnnounce(destinationHash []byte, announcedIdentity interface{}, appData []byte) error
	ReceivePathResponses() bool
}

func (t *Transport) RegisterAnnounceHandler(handler AnnounceHandler) {
	t.handlerLock.Lock()
	defer t.handlerLock.Unlock()

	// Check for duplicate handlers
	for _, h := range t.announceHandlers {
		if h == handler {
			return
		}
	}

	t.announceHandlers = append(t.announceHandlers, handler)
}

func (t *Transport) DeregisterAnnounceHandler(handler AnnounceHandler) {
	t.handlerLock.Lock()
	defer t.handlerLock.Unlock()
	for i, h := range t.announceHandlers {
		if h == handler {
			t.announceHandlers = append(t.announceHandlers[:i], t.announceHandlers[i+1:]...)
			return
		}
	}
}

func (t *Transport) HasPath(destinationHash []byte) bool {
	t.pathLock.RLock()
	defer t.pathLock.RUnlock()

	path, exists := t.paths[string(destinationHash)]
	if !exists {
		return false
	}

	// Check if path is still valid (not expired)
	if time.Since(path.LastUpdated) > time.Duration(PathRequestTTL)*time.Second {
		delete(t.paths, string(destinationHash))
		return false
	}

	return true
}

func (t *Transport) HopsTo(destinationHash []byte) uint8 {
	t.pathLock.RLock()
	defer t.pathLock.RUnlock()

	path, exists := t.paths[string(destinationHash)]
	if !exists {
		return PathfinderM
	}

	return path.Hops
}

func (t *Transport) NextHop(destinationHash []byte) []byte {
	t.pathLock.RLock()
	defer t.pathLock.RUnlock()

	path, exists := t.paths[string(destinationHash)]
	if !exists {
		return nil
	}

	return path.NextHop
}

func (t *Transport) NextHopInterface(destinationHash []byte) string {
	t.pathLock.RLock()
	defer t.pathLock.RUnlock()

	path, exists := t.paths[string(destinationHash)]
	if !exists {
		return ""
	}

	return path.Interface.GetName()
}

func (t *Transport) RequestPath(destinationHash []byte, onInterface string, tag []byte, recursive bool) error {
	packet := &PathRequest{
		DestinationHash: destinationHash,
		Tag:             tag,
		TTL:             PathRequestTTL,
		Recursive:       recursive,
	}

	if onInterface != "" {
		return t.sendPathRequest(packet, onInterface)
	}

	return t.broadcastPathRequest(packet)
}

func (t *Transport) UpdatePath(destinationHash []byte, nextHop []byte, interfaceName string, hops uint8) {
	t.pathLock.Lock()
	defer t.pathLock.Unlock()

	iface, err := t.GetInterface(interfaceName)
	if err != nil {
		return
	}

	t.paths[string(destinationHash)] = &common.Path{
		Interface:   iface,
		NextHop:     nextHop,
		Hops:        hops,
		LastUpdated: time.Now(),
	}
}

func (t *Transport) HandleAnnounce(destinationHash []byte, identity []byte, appData []byte, announceHash []byte) {
	t.handlerLock.RLock()
	defer t.handlerLock.RUnlock()

	for _, handler := range t.announceHandlers {
		if handler.ReceivePathResponses() || announceHash != nil {
			handler.ReceivedAnnounce(destinationHash, identity, appData)
		}
	}
}

func (t *Transport) NewDestination(identity interface{}, direction int, destType int, appName string, aspects ...string) *Destination {
	return &Destination{
		Identity:  identity,
		Direction: direction,
		Type:      destType,
		AppName:   appName,
		Aspects:   aspects,
	}
}

func (t *Transport) NewLink(dest []byte, establishedCallback func(), closedCallback func()) *Link {
	return NewLink(dest, establishedCallback, closedCallback)
}

type PathRequest struct {
	DestinationHash []byte
	Tag             []byte
	TTL             int
	Recursive       bool
}

type LinkPacket struct {
	Destination []byte
	Data        []byte
	Timestamp   time.Time
}

func (p *LinkPacket) send() error {
	// Get transport instance
	t := GetTransportInstance()

	// Create packet header
	header := make([]byte, 0, 64)
	header = append(header, 0x02) // Link packet type
	header = append(header, p.Destination...)

	// Add timestamp
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(p.Timestamp.Unix()))
	header = append(header, ts...)

	// Combine header and data
	packet := append(header, p.Data...)

	// Get next hop info
	nextHop := t.NextHop(p.Destination)
	if nextHop == nil {
		return errors.New("no path to destination")
	}

	// Get interface for next hop
	ifaceName := t.NextHopInterface(p.Destination)
	iface, ok := t.interfaces[ifaceName]
	if !ok {
		return errors.New("interface not found")
	}

	// Send packet using interface's Send method
	return iface.Send(packet, "")
}

func (t *Transport) sendPathRequest(req *PathRequest, interfaceName string) error {
	// Create path request packet
	packet := &PathRequestPacket{
		Type:            0x01,
		DestinationHash: req.DestinationHash,
		Tag:             req.Tag,
		TTL:             byte(req.TTL),
		Recursive:       req.Recursive,
	}

	// Serialize packet
	buf := make([]byte, 0, 128)
	buf = append(buf, packet.Type)
	buf = append(buf, packet.DestinationHash...)
	buf = append(buf, packet.Tag...)
	buf = append(buf, packet.TTL)
	if packet.Recursive {
		buf = append(buf, 0x01)
	} else {
		buf = append(buf, 0x00)
	}

	// Get interface
	iface, ok := t.interfaces[interfaceName]
	if !ok {
		return errors.New("interface not found")
	}

	return iface.Send(buf, "")
}

func (t *Transport) broadcastPathRequest(req *PathRequest) error {
	var lastErr error
	for _, iface := range t.interfaces {
		if !iface.IsEnabled() {
			continue
		}

		if err := t.sendPathRequest(req, iface.GetName()); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

type PathRequestPacket struct {
	Type            byte   // 0x01 for path request
	DestinationHash []byte // 32 bytes
	Tag             []byte // Variable length
	TTL             byte
	Recursive       bool
}

type NetworkInterface struct {
	Name    string
	Addr    *net.UDPAddr
	Conn    *net.UDPConn
	MTU     int
	Enabled bool
}

func SendAnnounce(packet []byte) error {
	t := GetTransportInstance()
	if t == nil {
		return errors.New("transport not initialized")
	}

	// Send announce packet to all interfaces
	var lastErr error
	for _, iface := range t.interfaces {
		if err := iface.Send(packet, ""); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

func (t *Transport) HandlePacket(data []byte, iface common.NetworkInterface) {
	if len(data) < 1 {
		return
	}

	packetType := data[0]
	switch packetType {
	case 0x01: // Path Request
		t.handlePathRequest(data[1:], iface)
	case 0x02: // Link Packet
		t.handleLinkPacket(data[1:], iface)
	case 0x03: // Path Response
		t.handlePathResponse(data[1:], iface)
	case 0x04: // Announce
		t.handleAnnouncePacket(data[1:], iface)
	}
}

func (t *Transport) handlePathRequest(data []byte, iface common.NetworkInterface) {
	if len(data) < 33 { // 32 bytes hash + 1 byte TTL minimum
		return
	}

	destHash := data[:32]
	ttl := data[32]
	var tag []byte
	recursive := false

	if len(data) > 33 {
		tag = data[33 : len(data)-1]
		recursive = data[len(data)-1] == 0x01
	}

	// Check if we have a path to the destination
	if t.HasPath(destHash) {
		// Create and send path response
		hops := t.HopsTo(destHash)
		nextHop := t.NextHop(destHash)

		response := make([]byte, 0, 64)
		response = append(response, 0x03) // Path Response type
		response = append(response, destHash...)
		response = append(response, byte(hops))
		response = append(response, nextHop...)
		if len(tag) > 0 {
			response = append(response, tag...)
		}

		iface.Send(response, "")
	} else if recursive && ttl > 0 {
		// Forward path request to other interfaces
		newData := make([]byte, len(data))
		copy(newData, data)
		newData[32] = ttl - 1 // Decrease TTL

		for name, otherIface := range t.interfaces {
			if name != iface.GetName() && otherIface.IsEnabled() {
				otherIface.Send(newData, "")
			}
		}
	}
}

func (t *Transport) handleLinkPacket(data []byte, iface common.NetworkInterface) {
	if len(data) < 40 { // 32 bytes dest + 8 bytes timestamp minimum
		return
	}

	dest := data[:32]
	timestamp := binary.BigEndian.Uint64(data[32:40])
	payload := data[40:]

	// Check if we're the destination
	if t.HasPath(dest) {
		nextHop := t.NextHop(dest)
		nextIfaceName := t.NextHopInterface(dest)

		// Only forward if received on different interface
		if nextIfaceName != iface.GetName() {
			if nextIface, ok := t.interfaces[nextIfaceName]; ok {
				nextIface.Send(data, string(nextHop))
			}
		}
	}

	// Update timing information
	if link := t.findLink(dest); link != nil {
		link.lastInbound = time.Unix(int64(timestamp), 0)
		if link.packetCb != nil {
			// Create a packet object to pass to callback
			p := &packet.Packet{
				Data: payload,
				// Add other necessary packet fields
			}
			link.packetCb(payload, p)
		}
	}
}

func (t *Transport) handlePathResponse(data []byte, iface common.NetworkInterface) {
	if len(data) < 33 { // 32 bytes hash + 1 byte hops minimum
		return
	}

	destHash := data[:32]
	hops := data[32]
	var nextHop []byte

	if len(data) > 33 {
		nextHop = data[33:]
	}

	// Use interface name when updating path
	if iface != nil {
		t.UpdatePath(destHash, nextHop, iface.GetName(), hops)
	}
}

func (t *Transport) handleAnnouncePacket(data []byte, iface common.NetworkInterface) {
	if len(data) < 32 {
		return
	}

	destHash := data[:32]
	var identityData, appData []byte

	if len(data) > 32 {
		splitPoint := 32
		for i := 32; i < len(data); i++ {
			if data[i] == 0x00 {
				splitPoint = i
				break
			}
		}
		identityData = data[32:splitPoint]
		if splitPoint < len(data)-1 {
			appData = data[splitPoint+1:]
		}
	}

	// Use identity package's GetRandomHash
	announceHash := identity.GetRandomHash()
	
	// Use interface name in announce handling
	if iface != nil {
		t.HandleAnnounce(destHash, identityData, appData, announceHash)
	}
}

func (t *Transport) findLink(dest []byte) *Link {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	// Use dest to lookup link in map
	if link, exists := t.links[string(dest)]; exists {
		return link
	}
	return nil
}

func (t *Transport) SendPacket(p *packet.Packet) error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	// Serialize packet
	data, err := p.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize packet: %w", err)
	}

	// Find appropriate interface
	destHash := p.Addresses[:packet.AddressSize]
	path, exists := t.paths[string(destHash)]
	if !exists {
		return errors.New("no path to destination")
	}

	// Send through interface
	if err := path.Interface.Send(data, ""); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

func (t *Transport) GetLink(destHash []byte) (*Link, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	link, exists := t.links[string(destHash)]
	if !exists {
		// Create new link if it doesn't exist
		link = NewLink(
			destHash,
			nil, // established callback
			nil, // closed callback
		)
		t.links[string(destHash)] = link
	}

	return link, nil
}

func (l *Link) OnConnected(cb func()) {
	l.connectedCb = cb
	if !l.establishedAt.IsZero() && cb != nil {
		cb()
	}
}

func (l *Link) OnDisconnected(cb func()) {
	l.disconnectedCb = cb
}

func (l *Link) GetRemoteIdentity() []byte {
	return l.remoteIdentity
}

func (l *Link) TrackPhyStats(track bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.physicalStats = track
}

func (l *Link) GetRSSI() int {
	// Implement physical layer stats
	return 0
}

func (l *Link) GetSNR() float64 {
	// Implement physical layer stats
	return 0
}

func (l *Link) GetQ() float64 {
	// Implement physical layer stats
	return 0
}

func (l *Link) SetResourceStrategy(strategy int) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if strategy != AcceptNone && strategy != AcceptAll && strategy != AcceptApp {
		return errors.New("invalid resource strategy")
	}

	l.resourceStrategy = strategy
	return nil
}

func (l *Link) SetResourceStartedCallback(cb func(interface{})) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceStartedCb = cb
}

func (l *Link) SetResourceConcludedCallback(cb func(interface{})) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceConcludedCb = cb
}

func (l *Link) SetRemoteIdentifiedCallback(cb func(*Link, []byte)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.remoteIdentifiedCb = cb
}

func (l *Link) HandleResource(resource interface{}) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	switch l.resourceStrategy {
	case AcceptNone:
		return false
	case AcceptAll:
		return true
	case AcceptApp:
		if l.resourceCb != nil {
			return l.resourceCb(resource)
		}
		return false
	default:
		return false
	}
}
