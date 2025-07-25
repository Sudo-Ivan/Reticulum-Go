package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
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

	// Announce packet types
	PACKET_TYPE_ANNOUNCE = 0x01
	PACKET_TYPE_LINK     = 0x02

	// Announce flags
	ANNOUNCE_NONE     = 0x00
	ANNOUNCE_PATH     = 0x01
	ANNOUNCE_IDENTITY = 0x02

	// Header types
	HEADER_TYPE_1 = 0x00 // One address field
	HEADER_TYPE_2 = 0x01 // Two address fields

	// Propagation types
	PROP_TYPE_BROADCAST = 0x00
	PROP_TYPE_TRANSPORT = 0x01

	// Destination types
	DEST_TYPE_SINGLE = 0x00
	DEST_TYPE_GROUP  = 0x01
	DEST_TYPE_PLAIN  = 0x02
	DEST_TYPE_LINK   = 0x03
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

func (t *Transport) HandleAnnounce(data []byte, sourceIface common.NetworkInterface) error {
	if len(data) < 53 { // Minimum size for announce packet
		return fmt.Errorf("announce packet too small: %d bytes", len(data))
	}

	log.Printf("[DEBUG-7] Transport handling announce of %d bytes from %s",
		len(data), sourceIface.GetName())

	// Parse announce fields according to RNS spec
	destHash := data[1:33]
	identity := data[33:49]
	appData := data[49:]

	// Generate announce hash to check for duplicates
	announceHash := sha256.Sum256(data)
	hashStr := string(announceHash[:])

	t.mutex.Lock()
	if _, seen := t.seenAnnounces[hashStr]; seen {
		t.mutex.Unlock()
		log.Printf("[DEBUG-7] Ignoring duplicate announce %x", announceHash[:8])
		return nil
	}
	t.seenAnnounces[hashStr] = true
	t.mutex.Unlock()

	// Don't forward if max hops reached
	if data[0] >= MAX_HOPS {
		log.Printf("[DEBUG-7] Announce exceeded max hops: %d", data[0])
		return nil
	}

	// Add random delay before retransmission (0-2 seconds)
	var delay time.Duration
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("[DEBUG-7] Failed to generate random delay: %v", err)
		delay = time.Duration(0) // Default to no delay on error
	} else {
                delay = time.Duration(binary.BigEndian.Uint64(b)%2000) * time.Millisecond // #nosec G115
	}
	time.Sleep(delay)

	// Check bandwidth allocation for announces
	if !t.announceRate.Allow() {
		log.Printf("[DEBUG-7] Announce rate limit exceeded, queuing...")
		return nil
	}

	// Increment hop count
	data[0]++

	// Broadcast to all other interfaces
	var lastErr error
	for name, iface := range t.interfaces {
		if iface == sourceIface || !iface.IsEnabled() {
			continue
		}

		log.Printf("[DEBUG-7] Forwarding announce on interface %s", name)
		if err := iface.Send(data, ""); err != nil {
			log.Printf("[DEBUG-7] Failed to forward announce on %s: %v", name, err)
			lastErr = err
		}
	}

	// Notify handlers
	t.notifyAnnounceHandlers(destHash, identity, appData)

	return lastErr
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
	binary.BigEndian.PutUint64(ts, uint64(p.Timestamp.Unix())) // #nosec G115
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
	if len(data) < 2 {
		log.Printf("[DEBUG-3] Dropping packet: insufficient length (%d bytes)", len(data))
		return
	}

	headerByte := data[0]
	packetType := headerByte & 0x03
	headerType := (headerByte & 0x40) >> 6
	contextFlag := (headerByte & 0x20) >> 5
	propType := (headerByte & 0x10) >> 4
	destType := (headerByte & 0x0C) >> 2

	log.Printf("[DEBUG-4] Packet received - Type: 0x%02x, Header: %d, Context: %d, PropType: %d, DestType: %d, Size: %d bytes",
		packetType, headerType, contextFlag, propType, destType, len(data))
	log.Printf("[DEBUG-5] Interface: %s, Raw header: 0x%02x", iface.GetName(), headerByte)

	if tcpIface, ok := iface.(*interfaces.TCPClientInterface); ok {
		tcpIface.UpdateStats(uint64(len(data)), true)
		log.Printf("[DEBUG-6] Updated TCP interface stats - RX bytes: %d", len(data))
	}

	switch packetType {
	case PACKET_TYPE_ANNOUNCE:
		log.Printf("[DEBUG-4] Processing announce packet")
		if err := t.handleAnnouncePacket(data, iface); err != nil {
			log.Printf("[DEBUG-3] Announce handling failed: %v", err)
		}
	case PACKET_TYPE_LINK:
		log.Printf("[DEBUG-4] Processing link packet")
		t.handleLinkPacket(data[1:], iface)
	case 0x03:
		log.Printf("[DEBUG-4] Processing path response")
		t.handlePathResponse(data[1:], iface)
	case 0x00:
		log.Printf("[DEBUG-4] Processing transport packet")
		t.handleTransportPacket(data[1:], iface)
	default:
		log.Printf("[DEBUG-3] Unknown packet type 0x%02x from %s", packetType, iface.GetName())
	}
}

func (t *Transport) handleAnnouncePacket(data []byte, iface common.NetworkInterface) error {
	if len(data) < 2 {
		return fmt.Errorf("packet too small for header")
	}

	// Parse header bytes according to RNS spec
	headerByte1 := data[0]
	hopCount := data[1]

	// Extract header fields
	ifacFlag := (headerByte1 & 0x80) >> 7    // IFAC flag in highest bit
	headerType := (headerByte1 & 0x40) >> 6  // Header type in next bit
	contextFlag := (headerByte1 & 0x20) >> 5 // Context flag
	propType := (headerByte1 & 0x10) >> 4    // Propagation type
	destType := (headerByte1 & 0x0C) >> 2    // Destination type in next 2 bits
	packetType := headerByte1 & 0x03         // Packet type in lowest 2 bits

	log.Printf("[DEBUG-5] Announce header: IFAC=%d, headerType=%d, context=%d, propType=%d, destType=%d, packetType=%d",
		ifacFlag, headerType, contextFlag, propType, destType, packetType)

	// Skip IFAC code if present
	startIdx := 2
	if ifacFlag == 1 {
		startIdx += 1 // For now assume 1 byte IFAC code
	}

	// Calculate address field size
	addrSize := 16
	if headerType == 1 {
		addrSize = 32 // Two address fields
	}

	// Validate minimum packet size
	minSize := startIdx + addrSize + 1 // Header + addresses + context
	if len(data) < minSize {
		return fmt.Errorf("packet too small: %d bytes", len(data))
	}

	// Extract fields
	addresses := data[startIdx : startIdx+addrSize]
	context := data[startIdx+addrSize]
	payload := data[startIdx+addrSize+1:]

	log.Printf("[DEBUG-6] Addresses: %x", addresses)
	log.Printf("[DEBUG-7] Context: %02x, Payload length: %d", context, len(payload))

	// Process payload (should contain pubkey + app data)
	if len(payload) < 32 { // Minimum size for pubkey
		return fmt.Errorf("payload too small for announce")
	}

	pubKey := payload[:32]
	appData := payload[32:]

	// Create identity from public key
	id := identity.FromPublicKey(pubKey)
	if id == nil {
		return fmt.Errorf("invalid identity")
	}

	// Generate announce hash to check for duplicates
	announceHash := sha256.Sum256(data)
	hashStr := string(announceHash[:])

	t.mutex.Lock()
	if _, seen := t.seenAnnounces[hashStr]; seen {
		t.mutex.Unlock()
		log.Printf("[DEBUG-7] Ignoring duplicate announce %x", announceHash[:8])
		return nil
	}
	t.seenAnnounces[hashStr] = true
	t.mutex.Unlock()

	// Don't forward if max hops reached
	if hopCount >= MAX_HOPS {
		log.Printf("[DEBUG-7] Announce exceeded max hops: %d", hopCount)
		return nil
	}

	// Add random delay before retransmission (0-2 seconds)
	var delay time.Duration
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("[DEBUG-7] Failed to generate random delay: %v", err)
		delay = time.Duration(0) // Default to no delay on error
	} else {
		delay = time.Duration(binary.BigEndian.Uint64(b)%2000) * time.Millisecond // #nosec G115
	}
	time.Sleep(delay)

	// Check bandwidth allocation for announces
	if !t.announceRate.Allow() {
		log.Printf("[DEBUG-7] Announce rate limit exceeded, queuing...")
		return nil
	}

	// Increment hop count
	data[1]++

	// Broadcast to all other interfaces
	var lastErr error
	for name, outIface := range t.interfaces {
		if outIface == iface || !outIface.IsEnabled() {
			continue
		}

		log.Printf("[DEBUG-7] Forwarding announce on interface %s", name)
		if err := outIface.Send(data, ""); err != nil {
			log.Printf("[DEBUG-7] Failed to forward announce on %s: %v", name, err)
			lastErr = err
		}
	}

	// Notify handlers with first address as destination hash
	t.notifyAnnounceHandlers(addresses[:16], id, appData)

	return lastErr
}

func (t *Transport) handleLinkPacket(data []byte, iface common.NetworkInterface) {
	if len(data) < 40 {
		log.Printf("[DEBUG-3] Dropping link packet: insufficient length (%d bytes)", len(data))
		return
	}

	dest := data[:32]
	timestamp := binary.BigEndian.Uint64(data[32:40])
	payload := data[40:]

	log.Printf("[DEBUG-5] Link packet - Destination: %x, Timestamp: %d, Payload: %d bytes",
		dest, timestamp, len(payload))

	if t.HasPath(dest) {
		nextHop := t.NextHop(dest)
		nextIfaceName := t.NextHopInterface(dest)
		log.Printf("[DEBUG-6] Found path - Next hop: %x, Interface: %s", nextHop, nextIfaceName)

		if nextIfaceName != iface.GetName() {
			if nextIface, ok := t.interfaces[nextIfaceName]; ok {
				log.Printf("[DEBUG-7] Forwarding link packet to %s", nextIfaceName)
				if err := nextIface.Send(data, string(nextHop)); err != nil { // #nosec G104
					log.Printf("[DEBUG-7] Failed to forward link packet: %v", err)
				}
			}
		}
	}

	if link := t.findLink(dest); link != nil {
		log.Printf("[DEBUG-6] Updating link timing - Last inbound: %v", time.Unix(int64(timestamp), 0)) // #nosec G115
		link.lastInbound = time.Unix(int64(timestamp), 0)                                               // #nosec G115
		if link.packetCb != nil {
			log.Printf("[DEBUG-7] Executing packet callback with %d bytes", len(payload))
			p := &packet.Packet{Data: payload}
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

func (t *Transport) handleTransportPacket(data []byte, iface common.NetworkInterface) {
	// Handle transport packet
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

	log.Printf("[DEBUG-4] Sending packet - Type: 0x%02x, Header: %d", p.PacketType, p.HeaderType)

	data, err := p.Serialize()
	if err != nil {
		log.Printf("[DEBUG-3] Packet serialization failed: %v", err)
		return fmt.Errorf("failed to serialize packet: %w", err)
	}
	log.Printf("[DEBUG-5] Serialized packet size: %d bytes", len(data))

	destHash := p.Addresses[:packet.AddressSize]
	log.Printf("[DEBUG-6] Destination hash: %x", destHash)

	path, exists := t.paths[string(destHash)]
	if !exists {
		log.Printf("[DEBUG-3] No path found for destination %x", destHash)
		return errors.New("no path to destination")
	}

	log.Printf("[DEBUG-5] Using path - Interface: %s, Next hop: %x, Hops: %d",
		path.Interface.GetName(), path.NextHop, path.HopCount)

	if err := path.Interface.Send(data, ""); err != nil {
		log.Printf("[DEBUG-3] Failed to send packet: %v", err)
		return fmt.Errorf("failed to send packet: %w", err)
	}

	log.Printf("[DEBUG-7] Packet sent successfully")
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

func CreateAnnouncePacket(destHash []byte, identity *identity.Identity, appData []byte, hops byte, config *common.ReticulumConfig) []byte {
	log.Printf("[DEBUG-7] Creating announce packet")
	log.Printf("[DEBUG-7] Input parameters: destHash=%x, appData=%x, hops=%d", destHash, appData, hops)

	// Create header (2 bytes)
	headerByte := byte(
		(0 << 7) | // Interface flag (IFAC_NONE)
			(0 << 6) | // Header type (HEADER_TYPE_1)
			(0 << 5) | // Context flag
			(0 << 4) | // Propagation type (BROADCAST)
			(0 << 2) | // Destination type (SINGLE)
			PACKET_TYPE_ANNOUNCE, // Packet type (0x01)
	)

	log.Printf("[DEBUG-7] Created header byte: 0x%02x, hops: %d", headerByte, hops)
	packet := []byte{headerByte, hops}
	log.Printf("[DEBUG-7] Initial packet size: %d bytes", len(packet))

	// Add destination hash (16 bytes)
	if len(destHash) > 16 {
		destHash = destHash[:16]
	}
	log.Printf("[DEBUG-7] Adding destination hash (16 bytes): %x", destHash)
	packet = append(packet, destHash...)
	log.Printf("[DEBUG-7] Packet size after adding destination hash: %d bytes", len(packet))

	// Get full public key and split into encryption and signing keys
	pubKey := identity.GetPublicKey()
	encKey := pubKey[:32]  // x25519 public key for encryption
	signKey := pubKey[32:] // Ed25519 public key for signing
	log.Printf("[DEBUG-7] Full public key: %x", pubKey)

	// Add encryption key (32 bytes)
	log.Printf("[DEBUG-7] Adding encryption key (32 bytes): %x", encKey)
	packet = append(packet, encKey...)
	log.Printf("[DEBUG-7] Packet size after adding encryption key: %d bytes", len(packet))

	// Add signing key (32 bytes)
	log.Printf("[DEBUG-7] Adding signing key (32 bytes): %x", signKey)
	packet = append(packet, signKey...)
	log.Printf("[DEBUG-7] Packet size after adding signing key: %d bytes", len(packet))

	// Add name hash (10 bytes)
	nameString := fmt.Sprintf("%s.%s", config.AppName, config.AppAspect)
	nameHash := sha256.Sum256([]byte(nameString))
	log.Printf("[DEBUG-7] Adding name hash (10 bytes): %x", nameHash[:10])
	packet = append(packet, nameHash[:10]...)
	log.Printf("[DEBUG-7] Packet size after adding name hash: %d bytes", len(packet))

	// Add random hash (10 bytes)
	randomBytes := make([]byte, 5)
	_, err := rand.Read(randomBytes) // #nosec G104
	if err != nil {
		log.Printf("[DEBUG-7] Failed to read random bytes: %v", err)
		return nil // Or handle the error appropriately
	}
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix())) // #nosec G115
	log.Printf("[DEBUG-7] Adding random hash (10 bytes): %x%x", randomBytes, timeBytes[:5])
	packet = append(packet, randomBytes...)
	packet = append(packet, timeBytes[:5]...)
	log.Printf("[DEBUG-7] Packet size after adding random hash: %d bytes", len(packet))

	// Create msgpack array for app data
	nameBytes := []byte(nameString)
	appDataMsg := []byte{0x92} // array of 2 elements

	// Add name as first element
	appDataMsg = append(appDataMsg, 0xc4)                 // bin 8 format
	appDataMsg = append(appDataMsg, byte(len(nameBytes))) // length
	appDataMsg = append(appDataMsg, nameBytes...)

	// Add app data as second element
	appDataMsg = append(appDataMsg, 0xc4)               // bin 8 format
	appDataMsg = append(appDataMsg, byte(len(appData))) // length
	appDataMsg = append(appDataMsg, appData...)

	// Create signature over destination hash and app data
	signData := append(destHash, appDataMsg...)
	signature := identity.Sign(signData)
	log.Printf("[DEBUG-7] Adding signature (64 bytes): %x", signature)
	packet = append(packet, signature...)
	log.Printf("[DEBUG-7] Packet size after adding signature: %d bytes", len(packet))

	// Finally add the app data message
	packet = append(packet, appDataMsg...)
	log.Printf("[DEBUG-7] Final packet size: %d bytes", len(packet))
	log.Printf("[DEBUG-7] Complete packet: %x", packet)

	return packet
}

func (t *Transport) GetInterfaces() map[string]common.NetworkInterface {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	interfaces := make(map[string]common.NetworkInterface, len(t.interfaces))
	for k, v := range t.interfaces {
		interfaces[k] = v
	}

	return interfaces
}

func (t *Transport) GetConfig() *common.ReticulumConfig {
	return t.config
}
