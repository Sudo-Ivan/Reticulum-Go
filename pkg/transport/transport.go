package transport

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/pathfinder"
	"github.com/Sudo-Ivan/reticulum-go/pkg/rate"
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

	// Link status constants
	STATUS_NEW    = 0
	STATUS_ACTIVE = 1
	STATUS_CLOSED = 2
	STATUS_FAILED = 3

	AnnounceRatePercent = 2.0  // 2% of bandwidth for announces
	PATHFINDER_M        = 8    // Maximum hop count
	AnnounceRateKbps    = 20.0 // 20 Kbps for announces

	MAX_HOPS         = 128  // Default m value for announce propagation
	PROPAGATION_RATE = 0.02 // 2% bandwidth cap for announces
)

type PathInfo struct {
	NextHop     []byte
	Interface   string
	Hops        uint8
	LastUpdated time.Time
}

type Transport struct {
	mutex            sync.RWMutex
	config           *common.ReticulumConfig
	interfaces       map[string]common.NetworkInterface
	links            map[string]*Link
	announceRate     *rate.Limiter
	seenAnnounces    map[string]bool
	pathfinder       *pathfinder.PathFinder
	announceHandlers []announce.Handler
	paths            map[string]*common.Path
}

type Path struct {
	NextHop   []byte
	Interface common.NetworkInterface
	HopCount  byte
}

func NewTransport(cfg *common.ReticulumConfig) *Transport {
	t := &Transport{
		interfaces:    make(map[string]common.NetworkInterface),
		paths:         make(map[string]*common.Path),
		seenAnnounces: make(map[string]bool),
		announceRate:  rate.NewLimiter(PROPAGATION_RATE, 1),
		mutex:         sync.RWMutex{},
		config:        cfg,
		links:         make(map[string]*Link),
		pathfinder:    pathfinder.NewPathFinder(),
	}
	return t
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
	status              int
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

func (l *Link) Send(data []byte) interface{} {
	l.mutex.Lock()
	l.lastOutbound = time.Now()
	l.lastData = time.Now()
	l.mutex.Unlock()

	packet := &LinkPacket{
		Destination: l.destination,
		Data:        data,
		Timestamp:   time.Now(),
	}

	if l.rtt == 0 {
		l.rtt = l.InactiveFor()
	}

	err := packet.send()
	if err != nil {
		return nil
	}

	return packet
}

func (t *Transport) RegisterAnnounceHandler(handler announce.Handler) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.announceHandlers = append(t.announceHandlers, handler)
}

func (t *Transport) UnregisterAnnounceHandler(handler announce.Handler) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for i, h := range t.announceHandlers {
		if h == handler {
			t.announceHandlers = append(t.announceHandlers[:i], t.announceHandlers[i+1:]...)
			break
		}
	}
}

func (t *Transport) notifyAnnounceHandlers(destHash []byte, identity interface{}, appData []byte) {
	t.mutex.RLock()
	handlers := make([]announce.Handler, len(t.announceHandlers))
	copy(handlers, t.announceHandlers)
	t.mutex.RUnlock()

	for _, handler := range handlers {
		if err := handler.ReceivedAnnounce(destHash, identity, appData); err != nil {
			log.Printf("Error in announce handler: %v", err)
		}
	}
}

func (t *Transport) HasPath(destinationHash []byte) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

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
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	path, exists := t.paths[string(destinationHash)]
	if !exists {
		return PathfinderM
	}

	return path.HopCount
}

func (t *Transport) NextHop(destinationHash []byte) []byte {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	path, exists := t.paths[string(destinationHash)]
	if !exists {
		return nil
	}

	return path.NextHop
}

func (t *Transport) NextHopInterface(destinationHash []byte) string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

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
	t.mutex.Lock()
	defer t.mutex.Unlock()

	iface, err := t.GetInterface(interfaceName)
	if err != nil {
		return
	}

	t.paths[string(destinationHash)] = &common.Path{
		NextHop:     nextHop,
		Interface:   iface,
		Hops:        hops,
		LastUpdated: time.Now(),
	}
}

func (t *Transport) HandleAnnounce(destinationHash []byte, identity []byte, appData []byte, announceHash []byte) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	t.notifyAnnounceHandlers(destinationHash, identity, appData)
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

	p := &packet.Packet{
		Data: data,
		Header: [2]byte{
			0x04, // Announce packet type
			0x00, // Initial hop count
		},
	}

	announceHash := sha256.Sum256(data)
	if t.seenAnnounces[string(announceHash[:])] {
		return
	}

	// Record this announce
	t.seenAnnounces[string(announceHash[:])] = true

	// Process the announce
	if err := t.handleAnnounce(p); err != nil {
		log.Printf("Error handling announce: %v", err)
		return
	}

	// Broadcast to other interfaces based on interface mode
	t.mutex.RLock()
	for name, otherIface := range t.interfaces {
		// Skip the interface we received from
		if name == iface.GetName() {
			continue
		}

		// Check interface modes for propagation rules
		srcMode := iface.GetMode()
		dstMode := otherIface.GetMode()

		// Skip propagation based on interface modes
		if srcMode == common.IF_MODE_ACCESS_POINT && dstMode != common.IF_MODE_FULL {
			continue
		}
		if srcMode == common.IF_MODE_ROAMING && dstMode == common.IF_MODE_ACCESS_POINT {
			continue
		}

		if err := otherIface.Send(p.Data, ""); err != nil {
			log.Printf("Error broadcasting announce to %s: %v", name, err)
		}
	}
	t.mutex.RUnlock()
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

func (t *Transport) Start() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return nil
}

// LinkInterface defines the methods required by Channel
type LinkInterface interface {
	GetStatus() int
	GetRTT() float64
	RTT() float64
	Send(data []byte) interface{}
	Resend(packet interface{}) error
	SetPacketTimeout(packet interface{}, callback func(interface{}), timeout time.Duration)
	SetPacketDelivered(packet interface{}, callback func(interface{}))
}

func (l *Link) GetRTT() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.rtt.Seconds()
}

func (l *Link) RTT() float64 {
	return l.GetRTT()
}

func (l *Link) Resend(p interface{}) error {
	if pkt, ok := p.(*packet.Packet); ok {
		t := GetTransportInstance()
		if t == nil {
			return fmt.Errorf("transport not initialized")
		}
		return t.SendPacket(pkt)
	}
	return fmt.Errorf("invalid packet type")
}

func (l *Link) SetPacketTimeout(p interface{}, callback func(interface{}), timeout time.Duration) {
	if pkt, ok := p.(*packet.Packet); ok {
		time.AfterFunc(timeout, func() {
			callback(pkt)
		})
	}
}

func (l *Link) SetPacketDelivered(p interface{}, callback func(interface{})) {
	if pkt, ok := p.(*packet.Packet); ok {
		l.mutex.Lock()
		l.rtt = time.Since(time.Now())
		l.mutex.Unlock()
		callback(pkt)
	}
}

func (l *Link) GetStatus() int {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.status
}

func (t *Transport) handleAnnounce(p *packet.Packet) error {
	// Skip if we've seen this announce before
	announceHash := sha256.Sum256(p.Data)
	if t.seenAnnounces[string(announceHash[:])] {
		return nil
	}

	// Record this announce
	t.seenAnnounces[string(announceHash[:])] = true

	// Extract announce fields
	if len(p.Data) < 53 { // Minimum size for announce packet
		return errors.New("invalid announce packet size")
	}

	// Don't forward if max hops reached
	if p.Header[1] >= MAX_HOPS {
		return nil
	}

	// Add random delay before retransmission (0-2 seconds)
	delay := time.Duration(rand.Float64() * 2 * float64(time.Second))
	time.Sleep(delay)

	// Check bandwidth allocation for announces
	if !t.announceRate.Allow() {
		return nil
	}

	// Increment hop count and retransmit
	p.Header[1]++
	return t.broadcastAnnouncePacket(p)
}

func (t *Transport) broadcastAnnouncePacket(p *packet.Packet) error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	for _, iface := range t.interfaces {
		if err := iface.Send(p.Data, ""); err != nil {
			return fmt.Errorf("failed to broadcast announce: %w", err)
		}
	}
	return nil
}
