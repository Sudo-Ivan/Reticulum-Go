package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
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
	mutex                 sync.RWMutex
	config                *common.ReticulumConfig
	interfaces            map[string]common.NetworkInterface
	links                 map[string]LinkInterface
	destinations          map[string]interface{}
	announceRate          *rate.Limiter
	seenAnnounces         map[string]bool
	pathfinder            *pathfinder.PathFinder
	announceHandlers      []announce.Handler
	paths                 map[string]*common.Path
	receipts              []*packet.PacketReceipt
	receiptsMutex         sync.RWMutex
	pathRequests          map[string]time.Time
	pathStates            map[string]byte
	discoveryPathRequests map[string]*DiscoveryPathRequest
	discoveryPRTags       map[string]bool
	announceTable         map[string]*PathAnnounceEntry
	heldAnnounces         map[string]*PathAnnounceEntry
	transportIdentity     *identity.Identity
	pathRequestDest       interface{}
}

type DiscoveryPathRequest struct {
	DestinationHash []byte
	Timeout         time.Time
	RequestingIface common.NetworkInterface
}

type PathAnnounceEntry struct {
	CreatedAt         time.Time
	RetransmitTimeout time.Time
	Retries           int
	ReceivedFrom      common.NetworkInterface
	AnnounceHops      byte
	Packet            *packet.Packet
	LocalRebroadcasts int
	BlockRebroadcasts bool
	AttachedInterface common.NetworkInterface
}

const (
	STATE_UNKNOWN      = 0x00
	STATE_UNRESPONSIVE = 0x01
	STATE_RESPONSIVE   = 0x02
)

type Path struct {
	NextHop   []byte
	Interface common.NetworkInterface
	HopCount  byte
}

func NewTransport(cfg *common.ReticulumConfig) *Transport {
	t := &Transport{
		interfaces:            make(map[string]common.NetworkInterface),
		paths:                 make(map[string]*common.Path),
		seenAnnounces:         make(map[string]bool),
		announceRate:          rate.NewLimiter(PROPAGATION_RATE, 1),
		mutex:                 sync.RWMutex{},
		config:                cfg,
		links:                 make(map[string]LinkInterface),
		destinations:          make(map[string]interface{}),
		pathfinder:            pathfinder.NewPathFinder(),
		receipts:              make([]*packet.PacketReceipt, 0),
		receiptsMutex:         sync.RWMutex{},
		pathRequests:          make(map[string]time.Time),
		pathStates:            make(map[string]byte),
		discoveryPathRequests: make(map[string]*DiscoveryPathRequest),
		discoveryPRTags:       make(map[string]bool),
		announceTable:         make(map[string]*PathAnnounceEntry),
		heldAnnounces:         make(map[string]*PathAnnounceEntry),
	}

	transportIdent, err := identity.LoadOrCreateTransportIdentity()
	if err == nil {
		t.transportIdentity = transportIdent
	}

	go t.startMaintenanceJobs()

	return t
}

func (t *Transport) startMaintenanceJobs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		t.cleanupExpiredPaths()
		t.cleanupExpiredDiscoveryRequests()
		t.cleanupExpiredAnnounces()
		t.cleanupExpiredReceipts()
	}
}

func (t *Transport) cleanupExpiredPaths() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	now := time.Now()
	pathExpiry := 7 * 24 * time.Hour

	for destHash, path := range t.paths {
		if now.Sub(path.LastUpdated) > pathExpiry {
			delete(t.paths, destHash)
			delete(t.pathStates, destHash)
			debug.Log(debug.DEBUG_VERBOSE, "Expired path", "dest_hash", fmt.Sprintf("%x", destHash[:8]))
		}
	}
}

func (t *Transport) cleanupExpiredDiscoveryRequests() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	now := time.Now()
	for destHash, req := range t.discoveryPathRequests {
		if now.After(req.Timeout) {
			delete(t.discoveryPathRequests, destHash)
			debug.Log(debug.DEBUG_VERBOSE, "Expired discovery path request", "dest_hash", fmt.Sprintf("%x", destHash[:8]))
		}
	}
}

func (t *Transport) cleanupExpiredAnnounces() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	announceExpiry := 24 * time.Hour

	for destHash, entry := range t.announceTable {
		if entry != nil && time.Since(entry.CreatedAt) > announceExpiry {
			delete(t.announceTable, destHash)
			debug.Log(debug.DEBUG_VERBOSE, "Expired announce entry", "dest_hash", fmt.Sprintf("%x", destHash[:8]))
		}
	}

	for destHash, entry := range t.heldAnnounces {
		if entry != nil && time.Since(entry.CreatedAt) > announceExpiry {
			delete(t.heldAnnounces, destHash)
		}
	}
}

func (t *Transport) cleanupExpiredReceipts() {
	t.receiptsMutex.Lock()
	defer t.receiptsMutex.Unlock()

	validReceipts := make([]*packet.PacketReceipt, 0)
	for _, receipt := range t.receipts {
		if receipt != nil && !receipt.IsTimedOut() {
			status := receipt.GetStatus()
			if status == packet.RECEIPT_SENT || status == packet.RECEIPT_DELIVERED {
				validReceipts = append(validReceipts, receipt)
			}
		}
	}

	if len(validReceipts) < len(t.receipts) {
		t.receipts = validReceipts
		debug.Log(debug.DEBUG_VERBOSE, "Cleaned up expired receipts", "remaining", len(validReceipts))
	}
}

func (t *Transport) MarkPathUnresponsive(destHash []byte) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.pathStates[string(destHash)] = STATE_UNRESPONSIVE
}

func (t *Transport) MarkPathResponsive(destHash []byte) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.pathStates[string(destHash)] = STATE_RESPONSIVE
}

func (t *Transport) PathIsUnresponsive(destHash []byte) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	state, exists := t.pathStates[string(destHash)]
	return exists && state == STATE_UNRESPONSIVE
}

// RegisterDestination registers a destination to receive incoming link requests
func (t *Transport) RegisterDestination(hash []byte, dest interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.destinations[string(hash)] = dest
	debug.Log(debug.DEBUG_TRACE, "Registered destination with transport", "hash", fmt.Sprintf("%x", hash))
}

// CreateIncomingLink creates a link object for an incoming link request
// This avoids circular import issues by having transport create the link
func (t *Transport) CreateIncomingLink(dest interface{}, networkIface common.NetworkInterface) interface{} {
	// This function signature uses interface{} to avoid importing link package
	// The actual implementation will be in the application code
	// For now, return nil to indicate links aren't fully implemented
	debug.Log(debug.DEBUG_TRACE, "CreateIncomingLink called (not yet fully implemented)")
	return nil
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
			debug.Log(debug.DEBUG_ERROR, "Error in announce handler", "error", err)
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

// updatePathUnlocked updates path without acquiring mutex (caller must hold lock)
func (t *Transport) updatePathUnlocked(destinationHash []byte, nextHop []byte, interfaceName string, hops uint8) {
	// Direct access to interfaces map since caller holds the lock
	iface, exists := t.interfaces[interfaceName]
	if !exists {
		debug.Log(debug.DEBUG_INFO, "Interface not found", "name", interfaceName)
		return
	}

	t.paths[string(destinationHash)] = &common.Path{
		NextHop:     nextHop,
		Interface:   iface,
		Hops:        hops,
		LastUpdated: time.Now(),
	}
}

func (t *Transport) UpdatePath(destinationHash []byte, nextHop []byte, interfaceName string, hops uint8) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.updatePathUnlocked(destinationHash, nextHop, interfaceName, hops)
}

func (t *Transport) HandleAnnounce(data []byte, sourceIface common.NetworkInterface) error {
	if len(data) < 53 { // Minimum size for announce packet
		return fmt.Errorf("announce packet too small: %d bytes", len(data))
	}

	debug.Log(debug.DEBUG_ALL, "Transport handling announce", "bytes", len(data), "source", sourceIface.GetName())

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
		debug.Log(debug.DEBUG_ALL, "Ignoring duplicate announce", "hash", fmt.Sprintf("%x", announceHash[:8]))
		return nil
	}
	t.seenAnnounces[hashStr] = true
	t.mutex.Unlock()

	// Don't forward if max hops reached
	if data[0] >= MAX_HOPS {
		debug.Log(debug.DEBUG_ALL, "Announce exceeded max hops", "hops", data[0])
		return nil
	}

	// Add random delay before retransmission (0-2 seconds)
	var delay time.Duration
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		debug.Log(debug.DEBUG_ALL, "Failed to generate random delay", "error", err)
		delay = time.Duration(0) // Default to no delay on error
	} else {
		delay = time.Duration(binary.BigEndian.Uint64(b)%2000) * time.Millisecond // #nosec G115
	}
	time.Sleep(delay)

	// Check bandwidth allocation for announces
	if !t.announceRate.Allow() {
		debug.Log(debug.DEBUG_ALL, "Announce rate limit exceeded, queuing")
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

		debug.Log(debug.DEBUG_ALL, "Forwarding announce on interface", "name", name)
		if err := iface.Send(data, ""); err != nil {
			debug.Log(debug.DEBUG_ALL, "Failed to forward announce", "name", name, "error", err)
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
		debug.Log(debug.DEBUG_INFO, "Dropping packet: insufficient length", "bytes", len(data))
		return
	}

	headerByte := data[0]
	packetType := headerByte & 0x03
	headerType := (headerByte & 0x40) >> 6
	contextFlag := (headerByte & 0x20) >> 5
	propType := (headerByte & 0x10) >> 4
	destType := (headerByte & 0x0C) >> 2

	debug.Log(debug.DEBUG_INFO, "TRANSPORT: Packet received", "type", fmt.Sprintf("0x%02x", packetType), "header", headerType, "context", contextFlag, "propType", propType, "destType", destType, "size", len(data))
	debug.Log(debug.DEBUG_TRACE, "Interface and raw header", "name", iface.GetName(), "header", fmt.Sprintf("0x%02x", headerByte))

	if len(data) == 67 {
		debug.Log(debug.DEBUG_ERROR, "67-byte packet detected", "header", fmt.Sprintf("0x%02x", headerByte), "packet_type_bits", fmt.Sprintf("0x%02x", packetType), "first_32_bytes", fmt.Sprintf("%x", data[:32]))
	}

	if tcpIface, ok := iface.(*interfaces.TCPClientInterface); ok {
		tcpIface.UpdateStats(uint64(len(data)), true)
		debug.Log(debug.DEBUG_PACKETS, "Updated TCP interface stats", "rx_bytes", len(data))
	}

	switch packetType {
	case PACKET_TYPE_ANNOUNCE:
		debug.Log(debug.DEBUG_VERBOSE, "Processing announce packet")
		if err := t.handleAnnouncePacket(data, iface); err != nil {
			debug.Log(debug.DEBUG_INFO, "Announce handling failed", "error", err)
		}
	case PACKET_TYPE_LINK:
		debug.Log(debug.DEBUG_ERROR, "Processing link packet (type=0x02)", "packet_size", len(data))
		t.handleLinkPacket(data[1:], iface, PACKET_TYPE_LINK)
	case packet.PacketTypeProof:
		debug.Log(debug.DEBUG_VERBOSE, "Processing proof packet")
		fullData := append([]byte{packet.PacketTypeProof}, data[1:]...)
		pkt := &packet.Packet{Raw: fullData}
		if err := pkt.Unpack(); err != nil {
			debug.Log(debug.DEBUG_INFO, "Failed to unpack proof packet", "error", err)
			return
		}
		t.handleProofPacket(pkt, iface)
	case 0x00:
		// Data packets with destType=2 are for established links
		if destType == 2 {
			debug.Log(debug.DEBUG_ERROR, "Processing link data packet (dest_type=2)", "packet_size", len(data))
			t.handleLinkPacket(data[1:], iface, 0x00)
		} else {
			debug.Log(debug.DEBUG_ERROR, "Processing data packet (type 0x00)", "packet_size", len(data), "dest_type", destType, "header_type", headerType)
			t.handleTransportPacket(data[1:], iface)
		}
	default:
		debug.Log(debug.DEBUG_INFO, "Unknown packet type", "type", fmt.Sprintf("0x%02x", packetType), "source", iface.GetName())
	}
}

func (t *Transport) handleAnnouncePacket(data []byte, iface common.NetworkInterface) error {
	debug.Log(debug.DEBUG_INFO, "Processing announce packet", "length", len(data))
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

	debug.Log(debug.DEBUG_TRACE, "Announce header", "ifac", ifacFlag, "headerType", headerType, "context", contextFlag, "propType", propType, "destType", destType, "packetType", packetType)

	// Skip IFAC code if present
	startIdx := 2
	if ifacFlag == 1 {
		startIdx++ // For now assume 1 byte IFAC code
	}

	// Announce packets use HEADER_TYPE_1 (single address field)
	// Calculate address field size
	addrSize := 16 // Always 16 bytes for HEADER_TYPE_1
	if headerType == 1 {
		// HEADER_TYPE_2 has two address fields
		addrSize = 32
	}

	// Validate minimum packet size
	minSize := startIdx + addrSize + 1 // Header + address(es) + context
	if len(data) < minSize {
		return fmt.Errorf("packet too small: %d bytes", len(data))
	}

	// Extract fields based on header type
	var destinationHash []byte
	var context byte
	var payload []byte

	if headerType == 0 {
		// HEADER_TYPE_1: Header(2) + DestHash(16) + Context(1) + Data
		destinationHash = data[startIdx : startIdx+16]
		context = data[startIdx+16]
		payload = data[startIdx+17:]
	} else {
		// HEADER_TYPE_2: Header(2) + TransportID(16) + DestHash(16) + Context(1) + Data
		// Skip transport ID, get destination hash
		destinationHash = data[startIdx+16 : startIdx+32]
		context = data[startIdx+32]
		payload = data[startIdx+33:]
	}

	debug.Log(debug.DEBUG_INFO, "Destination hash", "hash", fmt.Sprintf("%x", destinationHash))
	debug.Log(debug.DEBUG_INFO, "Context and payload", "context", fmt.Sprintf("%02x", context), "payload_len", len(payload))
	debug.Log(debug.DEBUG_INFO, "Packet total length", "length", len(data))

	// Parse announce packet according to RNS specification
	// Announce packets have the format:
	// [Public Key (64)][Name Hash (10)][Random Hash (10)][Ratchet (0 or 32)][Signature (64)][App Data]
	// Ratchet is present if context flag is set

	var id *identity.Identity
	var appData []byte
	var pubKey []byte

	minAnnounceSize := 64 + 10 + 10 + 64 // pubKey + nameHash + randomHash + signature
	if len(payload) < minAnnounceSize {
		debug.Log(debug.DEBUG_INFO, "Payload too small for announce", "bytes", len(payload), "minimum", minAnnounceSize)
		return fmt.Errorf("payload too small for announce")
	}

	// Parse the announce data
	pos := 0
	pubKey = payload[pos : pos+64] // 64 bytes: encKey (32) + signKey (32)
	pos += 64
	nameHash := payload[pos : pos+10]
	pos += 10
	randomHash := payload[pos : pos+10]
	pos += 10

	// Check if there's a ratchet based on context flag
	var ratchetData []byte
	if contextFlag == 1 {
		// Context flag is set, ratchet is present
		if len(payload) < pos+32+64 {
			debug.Log(debug.DEBUG_INFO, "Payload too small for announce with ratchet")
			return fmt.Errorf("payload too small for announce with ratchet")
		}
		ratchetData = payload[pos : pos+32]
		pos += 32
	}

	signature := payload[pos : pos+64]
	pos += 64
	appData = payload[pos:]

	ratchetHex := ""
	if len(ratchetData) > 0 {
		ratchetHex = fmt.Sprintf("%x", ratchetData[:8])
	} else {
		ratchetHex = "(none)"
	}
	debug.Log(debug.DEBUG_INFO, "Parsed announce", "pubKey", fmt.Sprintf("%x", pubKey[:8]), "nameHash", fmt.Sprintf("%x", nameHash), "randomHash", fmt.Sprintf("%x", randomHash), "ratchet", ratchetHex, "appData_len", len(appData))

	// Create identity from public key
	id = identity.FromPublicKey(pubKey)
	if id == nil {
		debug.Log(debug.DEBUG_INFO, "Failed to create identity from public key")
		return fmt.Errorf("invalid identity")
	}
	debug.Log(debug.DEBUG_INFO, "Successfully created identity")

	// Build signature data:
	// destination_hash + public_key + name_hash + random_hash + ratchet (if present) + app_data
	signData := make([]byte, 0)
	signData = append(signData, destinationHash...) // destination hash from packet header
	signData = append(signData, pubKey...)
	signData = append(signData, nameHash...)
	signData = append(signData, randomHash...)
	if len(ratchetData) > 0 {
		signData = append(signData, ratchetData...)
	}
	signData = append(signData, appData...)

	debug.Log(debug.DEBUG_INFO, "Verifying signature", "data_len", len(signData))

	// Verify signature
	if !id.Verify(signData, signature) {
		debug.Log(debug.DEBUG_INFO, "Signature verification failed - announce rejected")
		return fmt.Errorf("invalid announce signature")
	}
	debug.Log(debug.DEBUG_INFO, "Signature verification successful")

	// Validate destination hash according to RNS spec:
	// expected_hash = SHA256(name_hash + identity_hash)[:16]
	hashMaterial := make([]byte, 0)
	hashMaterial = append(hashMaterial, nameHash...)  // Name hash (10 bytes) first
	hashMaterial = append(hashMaterial, id.Hash()...) // Identity hash (16 bytes) second
	expectedHashFull := sha256.Sum256(hashMaterial)
	expectedHash := expectedHashFull[:16]

	debug.Log(debug.DEBUG_INFO, "Destination hash validation", "received", fmt.Sprintf("%x", destinationHash), "expected", fmt.Sprintf("%x", expectedHash))

	if string(destinationHash) != string(expectedHash) {
		debug.Log(debug.DEBUG_INFO, "Destination hash mismatch - announce rejected")
		return fmt.Errorf("destination hash mismatch")
	}
	debug.Log(debug.DEBUG_INFO, "Destination hash validation successful")

	// Log app_data content for accepted announces
	if len(appData) > 0 {
		debug.Log(debug.DEBUG_INFO, "Accepted announce with app_data", "data", fmt.Sprintf("%x", appData), "string", string(appData))
	}

	// Store the identity for later recall
	identity.Remember(data, destinationHash, pubKey, appData)

	// Generate announce hash to check for duplicates
	announceHash := sha256.Sum256(data)
	hashStr := string(announceHash[:])

	debug.Log(debug.DEBUG_INFO, "Announce hash", "hash", fmt.Sprintf("%x", announceHash[:8]))

	t.mutex.Lock()
	if _, seen := t.seenAnnounces[hashStr]; seen {
		t.mutex.Unlock()
		debug.Log(debug.DEBUG_INFO, "Ignoring duplicate announce", "hash", fmt.Sprintf("%x", announceHash[:8]))
		return nil
	}
	t.seenAnnounces[hashStr] = true
	t.mutex.Unlock()

	debug.Log(debug.DEBUG_INFO, "Processing new announce")

	// Register the path from this announce
	// The destination is reachable via the interface that received this announce
	if iface != nil {
		// Use unlocked version since we may be called in a locked context
		t.mutex.Lock()
		t.updatePathUnlocked(destinationHash, nil, iface.GetName(), hopCount)
		t.mutex.Unlock()
		debug.Log(debug.DEBUG_INFO, "Registered path", "hash", fmt.Sprintf("%x", destinationHash), "interface", iface.GetName(), "hops", hopCount)
	}

	// Notify handlers first, regardless of forwarding limits
	debug.Log(debug.DEBUG_INFO, "Notifying announce handlers", "destHash", fmt.Sprintf("%x", destinationHash), "appDataLen", len(appData))
	t.notifyAnnounceHandlers(destinationHash, id, appData)
	debug.Log(debug.DEBUG_INFO, "Announce handlers notified")

	// Don't forward if max hops reached
	if hopCount >= MAX_HOPS {
		debug.Log(debug.DEBUG_INFO, "Announce exceeded max hops", "hops", hopCount)
		return nil
	}
	debug.Log(debug.DEBUG_INFO, "Hop count OK", "hops", hopCount)

	// Check bandwidth allocation for announces
	if !t.announceRate.Allow() {
		debug.Log(debug.DEBUG_INFO, "Announce rate limit exceeded, not forwarding")
		return nil
	}
	debug.Log(debug.DEBUG_INFO, "Bandwidth check passed")

	// Add random delay before retransmission (0-2 seconds)
	var delay time.Duration
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		debug.Log(debug.DEBUG_ALL, "Failed to generate random delay", "error", err)
		delay = time.Duration(0) // Default to no delay on error
	} else {
		delay = time.Duration(binary.BigEndian.Uint64(b)%2000) * time.Millisecond // #nosec G115
	}
	time.Sleep(delay)

	// Increment hop count
	data[1]++

	// Broadcast to all other interfaces
	var lastErr error
	for name, outIface := range t.interfaces {
		if outIface == iface || !outIface.IsEnabled() {
			continue
		}

		debug.Log(debug.DEBUG_ALL, "Forwarding announce on interface", "name", name)
		if err := outIface.Send(data, ""); err != nil {
			debug.Log(debug.DEBUG_ALL, "Failed to forward announce", "name", name, "error", err)
			lastErr = err
		}
	}

	return lastErr
}

func (t *Transport) handleLinkPacket(data []byte, iface common.NetworkInterface, packetType byte) {
	debug.Log(debug.DEBUG_ERROR, "Handling link packet", "bytes", len(data), "packet_type", fmt.Sprintf("0x%02x", packetType), "PACKET_TYPE_LINK", fmt.Sprintf("0x%02x", PACKET_TYPE_LINK))

	pkt := &packet.Packet{}

	// If this is a LINKREQUEST packet (type=0x02), handle it as link establishment
	if packetType == PACKET_TYPE_LINK {
		debug.Log(debug.DEBUG_ERROR, "Processing LINKREQUEST (type=0x02)")

		// Parse as LINKREQUEST packet - prepend the packet type
		pkt.Raw = append([]byte{PACKET_TYPE_LINK}, data...)
		if err := pkt.Unpack(); err != nil {
			debug.Log(debug.DEBUG_ERROR, "Failed to unpack link request", "error", err)
			return
		}

		destHash := pkt.DestinationHash
		if len(destHash) > 16 {
			destHash = destHash[:16]
		}

		debug.Log(debug.DEBUG_ERROR, "Link request for destination", "hash", fmt.Sprintf("%x", destHash))

		// Look up the destination
		t.mutex.RLock()
		destIface, exists := t.destinations[string(destHash)]
		t.mutex.RUnlock()

		if !exists {
			debug.Log(debug.DEBUG_ERROR, "No destination registered for hash", "hash", fmt.Sprintf("%x", destHash))
			return
		}

		debug.Log(debug.DEBUG_ERROR, "Found registered destination", "hash", fmt.Sprintf("%x", destHash))

		// Handle the incoming link request
		t.handleIncomingLinkRequest(pkt, destIface, iface)
		return
	}

	// Otherwise, this is a data packet for an established link (destType=2, packetType=0x00)
	debug.Log(debug.DEBUG_ERROR, "Processing link data packet")

	// Parse as data packet - prepend packet type 0x00
	pkt.Raw = append([]byte{0x00}, data...)
	if err := pkt.Unpack(); err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to unpack link data packet", "error", err)
		return
	}

	// For link data packets, the destination hash is actually the link ID
	linkID := pkt.DestinationHash
	if len(linkID) > 16 {
		linkID = linkID[:16]
	}

	debug.Log(debug.DEBUG_ERROR, "Link data for link ID", "link_id", fmt.Sprintf("%x", linkID))

	// Find the established link
	t.mutex.RLock()
	linkObj, exists := t.links[string(linkID)]
	t.mutex.RUnlock()

	if exists && linkObj != nil {
		debug.Log(debug.DEBUG_VERBOSE, "Routing packet to established link")
		if err := linkObj.HandleInbound(pkt); err != nil {
			debug.Log(debug.DEBUG_ERROR, "Error handling inbound packet", "error", err)
		}
	} else {
		debug.Log(debug.DEBUG_INFO, "No established link found for link ID", "link_id", fmt.Sprintf("%x", linkID))
	}
}

func (t *Transport) handleIncomingLinkRequest(pkt *packet.Packet, destIface interface{}, networkIface common.NetworkInterface) {
	debug.Log(debug.DEBUG_TRACE, "Handling incoming link request")

	// The link ID is in the packet data
	linkID := pkt.Data
	if len(linkID) == 0 {
		debug.Log(debug.DEBUG_INFO, "No link ID in link request packet")
		return
	}

	debug.Log(debug.DEBUG_TRACE, "Link request with ID", "id", fmt.Sprintf("%x", linkID[:8]))

	// Call the destination's HandleIncomingLinkRequest method
	destValue := reflect.ValueOf(destIface)
	if destValue.IsValid() && !destValue.IsNil() {
		method := destValue.MethodByName("HandleIncomingLinkRequest")
		if method.IsValid() {
			// HandleIncomingLinkRequest(pkt interface{}, transport interface{}, networkIface common.NetworkInterface) error
			args := []reflect.Value{
				reflect.ValueOf(pkt),
				reflect.ValueOf(t),
				reflect.ValueOf(networkIface),
			}
			results := method.Call(args)
			if len(results) > 0 && !results[0].IsNil() {
				err := results[0].Interface().(error)
				debug.Log(debug.DEBUG_ERROR, "Failed to handle incoming link request", "error", err)
			} else {
				debug.Log(debug.DEBUG_VERBOSE, "Link request handled successfully by destination")
			}
		} else {
			debug.Log(debug.DEBUG_INFO, "Destination does not have HandleIncomingLinkRequest method")
		}
	} else {
		debug.Log(debug.DEBUG_INFO, "Invalid destination object")
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
	if len(data) < 2 {
		return
	}

	headerByte := data[0]
	packetType := headerByte & 0x03
	destType := (headerByte & 0x0C) >> 2

	if packetType == packet.PacketTypeData && destType == DEST_TYPE_PLAIN {
		if len(data) < 19 {
			return
		}

		context := data[18]

		if context == packet.ContextPathResponse {
			t.handlePathResponse(data[19:], iface)
		}
	}
}

func (t *Transport) InitializePathRequestHandler() error {
	if t.transportIdentity == nil {
		return errors.New("transport identity not initialized")
	}

	pathRequestDest, err := destination.New(t.transportIdentity, destination.IN, destination.PLAIN, "rnstransport", t, "path", "request")
	if err != nil {
		return fmt.Errorf("failed to create path request destination: %w", err)
	}

	pathRequestDest.SetPacketCallback(func(data []byte, iface common.NetworkInterface) {
		t.handlePathRequest(data, iface)
	})

	pathRequestDest.AcceptsLinks(true)
	t.pathRequestDest = pathRequestDest
	t.RegisterDestination(pathRequestDest.GetHash(), pathRequestDest)

	debug.Log(debug.DEBUG_INFO, "Path request handler initialized")
	return nil
}

func (t *Transport) handlePathRequest(data []byte, iface common.NetworkInterface) {
	if len(data) < identity.TRUNCATED_HASHLENGTH/8 {
		debug.Log(debug.DEBUG_INFO, "Path request too short")
		return
	}

	destHash := data[:identity.TRUNCATED_HASHLENGTH/8]
	var requestorTransportID []byte
	var tag []byte

	if len(data) > identity.TRUNCATED_HASHLENGTH/8*2 {
		requestorTransportID = data[identity.TRUNCATED_HASHLENGTH/8 : identity.TRUNCATED_HASHLENGTH/8*2]
		tag = data[identity.TRUNCATED_HASHLENGTH/8*2:]
		if len(tag) > identity.TRUNCATED_HASHLENGTH/8 {
			tag = tag[:identity.TRUNCATED_HASHLENGTH/8]
		}
	} else if len(data) > identity.TRUNCATED_HASHLENGTH/8 {
		tag = data[identity.TRUNCATED_HASHLENGTH/8:]
		if len(tag) > identity.TRUNCATED_HASHLENGTH/8 {
			tag = tag[:identity.TRUNCATED_HASHLENGTH/8]
		}
	}

	if tag == nil {
		debug.Log(debug.DEBUG_INFO, "Ignoring tagless path request", "dest_hash", fmt.Sprintf("%x", destHash))
		return
	}

	uniqueTag := append(destHash, tag...)
	tagStr := string(uniqueTag)

	t.mutex.Lock()
	if t.discoveryPRTags[tagStr] {
		t.mutex.Unlock()
		debug.Log(debug.DEBUG_INFO, "Ignoring duplicate path request", "dest_hash", fmt.Sprintf("%x", destHash), "tag", fmt.Sprintf("%x", tag))
		return
	}
	t.discoveryPRTags[tagStr] = true
	if len(t.discoveryPRTags) > 32000 {
		t.discoveryPRTags = make(map[string]bool)
	}
	t.mutex.Unlock()

	t.processPathRequest(destHash, iface, requestorTransportID, tag)
}

func (t *Transport) processPathRequest(destHash []byte, attachedIface common.NetworkInterface, requestorTransportID []byte, tag []byte) {
	destHashStr := string(destHash)
	debug.Log(debug.DEBUG_INFO, "Processing path request", "dest_hash", fmt.Sprintf("%x", destHash))

	t.mutex.RLock()
	localDest, isLocal := t.destinations[destHashStr]
	path, hasPath := t.paths[destHashStr]
	t.mutex.RUnlock()

	if isLocal {
		if dest, ok := localDest.(*destination.Destination); ok {
			debug.Log(debug.DEBUG_INFO, "Answering path request for local destination", "dest_hash", fmt.Sprintf("%x", destHash))
			dest.Announce(true, tag, attachedIface)
		}
		return
	}

	if hasPath {
		nextHop := path.NextHop
		if requestorTransportID != nil && string(nextHop) == string(requestorTransportID) {
			debug.Log(debug.DEBUG_INFO, "Not answering path request, next hop is requestor", "dest_hash", fmt.Sprintf("%x", destHash))
			return
		}

		debug.Log(debug.DEBUG_INFO, "Answering path request with known path", "dest_hash", fmt.Sprintf("%x", destHash), "hops", path.HopCount)

		t.mutex.RLock()
		announceEntry, hasAnnounce := t.announceTable[destHashStr]
		t.mutex.RUnlock()

		if hasAnnounce && announceEntry != nil {
			now := time.Now()
			retries := 1
			localRebroadcasts := 0
			blockRebroadcasts := true
			announceHops := path.HopCount

			retransmitTimeout := now.Add(time.Duration(400) * time.Millisecond)

			entry := &PathAnnounceEntry{
				CreatedAt:         now,
				RetransmitTimeout: retransmitTimeout,
				Retries:           retries,
				ReceivedFrom:      path.Interface,
				AnnounceHops:      announceHops,
				Packet:            announceEntry.Packet,
				LocalRebroadcasts: localRebroadcasts,
				BlockRebroadcasts: blockRebroadcasts,
				AttachedInterface: attachedIface,
			}

			t.mutex.Lock()
			if _, held := t.announceTable[destHashStr]; held {
				t.heldAnnounces[destHashStr] = t.announceTable[destHashStr]
			}
			t.announceTable[destHashStr] = entry
			t.mutex.Unlock()
		}
		return
	}

	if attachedIface != nil {
		debug.Log(debug.DEBUG_INFO, "Attempting to discover unknown path", "dest_hash", fmt.Sprintf("%x", destHash))

		t.mutex.Lock()
		if _, exists := t.discoveryPathRequests[destHashStr]; exists {
			t.mutex.Unlock()
			debug.Log(debug.DEBUG_INFO, "Path request already pending", "dest_hash", fmt.Sprintf("%x", destHash))
			return
		}

		prEntry := &DiscoveryPathRequest{
			DestinationHash: destHash,
			Timeout:         time.Now().Add(15 * time.Second),
			RequestingIface: attachedIface,
		}
		t.discoveryPathRequests[destHashStr] = prEntry
		t.mutex.Unlock()

		for name, iface := range t.interfaces {
			if iface != attachedIface && iface.IsEnabled() {
				req := &PathRequest{
					DestinationHash: destHash,
					Tag:             tag,
					TTL:             15,
					Recursive:       true,
				}
				t.sendPathRequest(req, name)
			}
		}
	} else {
		debug.Log(debug.DEBUG_INFO, "Ignoring path request, no path known", "dest_hash", fmt.Sprintf("%x", destHash))
	}
}

func (t *Transport) SendPacket(p *packet.Packet) error {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	debug.Log(debug.DEBUG_VERBOSE, "Sending packet", "type", fmt.Sprintf("0x%02x", p.PacketType), "header", p.HeaderType)

	data, err := p.Serialize()
	if err != nil {
		debug.Log(debug.DEBUG_INFO, "Packet serialization failed", "error", err)
		return fmt.Errorf("failed to serialize packet: %w", err)
	}
	debug.Log(debug.DEBUG_TRACE, "Serialized packet size", "bytes", len(data))

	// Use the DestinationHash field directly for path lookup
	destHash := p.DestinationHash
	if len(destHash) > 16 {
		destHash = destHash[:16]
	}
	debug.Log(debug.DEBUG_PACKETS, "Destination hash", "hash", fmt.Sprintf("%x", destHash))

	path, exists := t.paths[string(destHash)]
	if !exists {
		debug.Log(debug.DEBUG_INFO, "No path found for destination", "hash", fmt.Sprintf("%x", destHash))
		return errors.New("no path to destination")
	}

	debug.Log(debug.DEBUG_TRACE, "Using path", "interface", path.Interface.GetName(), "nextHop", fmt.Sprintf("%x", path.NextHop), "hops", path.HopCount)

	if err := path.Interface.Send(data, ""); err != nil {
		debug.Log(debug.DEBUG_INFO, "Failed to send packet", "error", err)
		return fmt.Errorf("failed to send packet: %w", err)
	}

	p.Sent = true
	p.SentAt = time.Now()

	if p.CreateReceipt {
		receipt := packet.NewPacketReceipt(p)
		t.RegisterReceipt(receipt)
		debug.Log(debug.DEBUG_PACKETS, "Created packet receipt")
	}

	debug.Log(debug.DEBUG_ALL, "Packet sent successfully")
	return nil
}

func (t *Transport) RegisterLink(linkID []byte, linkObj LinkInterface) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(linkID) > 16 {
		linkID = linkID[:16]
	}

	t.links[string(linkID)] = linkObj
	debug.Log(debug.DEBUG_VERBOSE, "Registered link", "link_id", fmt.Sprintf("%x", linkID))
}

func (t *Transport) UnregisterLink(linkID []byte) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(linkID) > 16 {
		linkID = linkID[:16]
	}
	delete(t.links, string(linkID))
	debug.Log(debug.DEBUG_VERBOSE, "Unregistered link", "link_id", fmt.Sprintf("%x", linkID))
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
	GetStatus() byte
	GetRTT() float64
	RTT() float64
	GetLinkID() []byte
	Send(data []byte) interface{}
	Resend(packet interface{}) error
	SetPacketTimeout(packet interface{}, callback func(interface{}), timeout time.Duration)
	SetPacketDelivered(packet interface{}, callback func(interface{}))
	HandleInbound(pkt *packet.Packet) error
	ValidateLinkProof(pkt *packet.Packet) error
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

func CreateAnnouncePacket(destHash []byte, identity *identity.Identity, appData []byte, destName string, hops byte, config *common.ReticulumConfig) []byte {
	debug.Log(debug.DEBUG_INFO, "Creating announce packet", "destName", destName)
	debug.Log(debug.DEBUG_INFO, "Input", "destHash", fmt.Sprintf("%x", destHash[:8]), "appData", string(appData), "hops", hops)

	// Create header (2 bytes)
	headerByte := byte(
		(0 << 7) | // Interface flag (IFAC_NONE)
			(0 << 6) | // Header type (HEADER_TYPE_1)
			(0 << 5) | // Context flag
			(0 << 4) | // Propagation type (BROADCAST)
			(0 << 2) | // Destination type (SINGLE)
			PACKET_TYPE_ANNOUNCE, // Packet type (0x01)
	)

	debug.Log(debug.DEBUG_ALL, "Created header byte", "header", fmt.Sprintf("0x%02x", headerByte), "hops", hops)
	packet := []byte{headerByte, hops}
	debug.Log(debug.DEBUG_ALL, "Initial packet size", "bytes", len(packet))

	// Add destination hash (16 bytes)
	if len(destHash) > 16 {
		destHash = destHash[:16]
	}
	debug.Log(debug.DEBUG_ALL, "Adding destination hash (16 bytes)", "hash", fmt.Sprintf("%x", destHash))
	packet = append(packet, destHash...)
	debug.Log(debug.DEBUG_ALL, "Packet size after adding destination hash", "bytes", len(packet))

	// Get full public key and split into encryption and signing keys
	pubKey := identity.GetPublicKey()
	encKey := pubKey[:32]  // x25519 public key for encryption
	signKey := pubKey[32:] // Ed25519 public key for signing
	debug.Log(debug.DEBUG_ALL, "Full public key", "key", fmt.Sprintf("%x", pubKey))

	// Add encryption key (32 bytes)
	debug.Log(debug.DEBUG_ALL, "Adding encryption key (32 bytes)", "key", fmt.Sprintf("%x", encKey))
	packet = append(packet, encKey...)
	debug.Log(debug.DEBUG_ALL, "Packet size after adding encryption key", "bytes", len(packet))

	// Add signing key (32 bytes)
	debug.Log(debug.DEBUG_ALL, "Adding signing key (32 bytes)", "key", fmt.Sprintf("%x", signKey))
	packet = append(packet, signKey...)
	debug.Log(debug.DEBUG_ALL, "Packet size after adding signing key", "bytes", len(packet))

	// Add name hash (10 bytes)
	nameHash := sha256.Sum256([]byte(destName))
	debug.Log(debug.DEBUG_ALL, "Adding name hash (10 bytes)", "destName", destName, "hash", fmt.Sprintf("%x", nameHash[:10]))
	packet = append(packet, nameHash[:10]...)
	debug.Log(debug.DEBUG_ALL, "Packet size after adding name hash", "bytes", len(packet))

	// Add random hash (10 bytes)
	randomBytes := make([]byte, 5)
	_, err := rand.Read(randomBytes) // #nosec G104
	if err != nil {
		debug.Log(debug.DEBUG_ALL, "Failed to read random bytes", "error", err)
		return nil // Or handle the error appropriately
	}
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix())) // #nosec G115
	debug.Log(debug.DEBUG_ALL, "Adding random hash (10 bytes)", "random", fmt.Sprintf("%x", randomBytes), "time", fmt.Sprintf("%x", timeBytes[:5]))
	packet = append(packet, randomBytes...)
	packet = append(packet, timeBytes[:5]...)
	debug.Log(debug.DEBUG_ALL, "Packet size after adding random hash", "bytes", len(packet))

	// Create msgpack array for app data
	nameBytes := []byte(destName)
	appDataMsg := []byte{0x92} // array of 2 elements

	// Add name as first element
	appDataMsg = append(appDataMsg, 0xc4, byte(len(nameBytes)))
	appDataMsg = append(appDataMsg, nameBytes...)

	// Add app data as second element
	appDataMsg = append(appDataMsg, 0xc4, byte(len(appData)))
	appDataMsg = append(appDataMsg, appData...)

	// Create signature over destination hash and app data
	signData := append(destHash, appDataMsg...)
	signature := identity.Sign(signData)
	debug.Log(debug.DEBUG_ALL, "Adding signature (64 bytes)", "signature", fmt.Sprintf("%x", signature))
	packet = append(packet, signature...)
	debug.Log(debug.DEBUG_ALL, "Packet size after adding signature", "bytes", len(packet))

	// Finally add the app data message
	packet = append(packet, appDataMsg...)
	debug.Log(debug.DEBUG_INFO, "Final packet size", "bytes", len(packet))
	debug.Log(debug.DEBUG_INFO, "appDataMsg", "data", fmt.Sprintf("%x", appDataMsg), "len", len(appDataMsg))

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

func (t *Transport) RegisterReceipt(receipt *packet.PacketReceipt) {
	t.receiptsMutex.Lock()
	defer t.receiptsMutex.Unlock()
	t.receipts = append(t.receipts, receipt)
	debug.Log(debug.DEBUG_PACKETS, "Registered packet receipt", "hash", fmt.Sprintf("%x", receipt.GetHash()[:8]))
}

func (t *Transport) UnregisterReceipt(receipt *packet.PacketReceipt) {
	t.receiptsMutex.Lock()
	defer t.receiptsMutex.Unlock()

	for i, r := range t.receipts {
		if r == receipt {
			t.receipts = append(t.receipts[:i], t.receipts[i+1:]...)
			debug.Log(debug.DEBUG_PACKETS, "Unregistered packet receipt")
			return
		}
	}
}

func (t *Transport) handleProofPacket(pkt *packet.Packet, iface common.NetworkInterface) {
	debug.Log(debug.DEBUG_PACKETS, "Processing proof packet", "size", len(pkt.Data), "context", fmt.Sprintf("0x%02x", pkt.Context))

	if pkt.Context == packet.ContextLRProof {
		linkID := pkt.DestinationHash
		if len(linkID) > 16 {
			linkID = linkID[:16]
		}

		t.mutex.RLock()
		link, exists := t.links[string(linkID)]
		t.mutex.RUnlock()

		if exists && link != nil {
			if err := link.ValidateLinkProof(pkt); err != nil {
				debug.Log(debug.DEBUG_ERROR, "Link proof validation failed", "error", err)
			} else {
				debug.Log(debug.DEBUG_INFO, "Link proof validated successfully")
			}
			return
		}
		debug.Log(debug.DEBUG_INFO, "No link found for proof packet", "link_id", fmt.Sprintf("%x", linkID))
		return
	}

	var proofHash []byte
	if len(pkt.Data) == packet.EXPL_LENGTH {
		proofHash = pkt.Data[:identity.HASHLENGTH/8]
		debug.Log(debug.DEBUG_PACKETS, "Explicit proof", "hash", fmt.Sprintf("%x", proofHash[:8]))
	} else {
		debug.Log(debug.DEBUG_PACKETS, "Implicit proof")
	}

	t.receiptsMutex.RLock()
	receipts := make([]*packet.PacketReceipt, len(t.receipts))
	copy(receipts, t.receipts)
	t.receiptsMutex.RUnlock()

	for _, receipt := range receipts {
		receiptValidated := false

		if proofHash != nil {
			receiptHash := receipt.GetHash()
			if string(receiptHash) == string(proofHash) {
				receiptValidated = receipt.ValidateProofPacket(pkt)
			}
		} else {
			receiptValidated = receipt.ValidateProofPacket(pkt)
		}

		if receiptValidated {
			debug.Log(debug.DEBUG_PACKETS, "Proof validated for receipt")
			t.UnregisterReceipt(receipt)
			return
		}
	}

	debug.Log(debug.DEBUG_PACKETS, "No matching receipt for proof")
}
