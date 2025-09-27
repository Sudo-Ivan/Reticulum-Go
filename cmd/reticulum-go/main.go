package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/buffer"
	"github.com/Sudo-Ivan/reticulum-go/pkg/channel"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

var (
	debugLevel       = flag.Int("debug", 7, "Debug level (0-7)")
	interceptPackets = flag.Bool("intercept-packets", false, "Enable packet interception")
	interceptOutput  = flag.String("intercept-output", "packets.log", "Output file for intercepted packets")
)

func debugLog(level int, format string, v ...interface{}) {
	if *debugLevel >= level {
		log.Printf("[DEBUG-%d] %s", level, fmt.Sprintf(format, v...))
	}
}

const (
	ANNOUNCE_RATE_TARGET  = 3600 // Default target time between announces (1 hour)
	ANNOUNCE_RATE_GRACE   = 3    // Number of grace announces before enforcing rate
	ANNOUNCE_RATE_PENALTY = 7200 // Additional penalty time for rate violations
	MAX_ANNOUNCE_HOPS     = 128  // Maximum number of hops for announces
	DEBUG_CRITICAL        = 1    // Critical errors
	DEBUG_ERROR           = 2    // Non-critical errors
	DEBUG_INFO            = 3    // Important information
	DEBUG_VERBOSE         = 4    // Detailed information
	DEBUG_TRACE           = 5    // Very detailed tracing
	DEBUG_PACKETS         = 6    // Packet-level details
	DEBUG_ALL             = 7    // Everything including identity operations
	APP_NAME              = "Go-Client"
	APP_ASPECT            = "node" // Always use "node" for node announces
)

type Reticulum struct {
	config            *common.ReticulumConfig
	transport         *transport.Transport
	interfaces        []interfaces.Interface
	channels          map[string]*channel.Channel
	buffers           map[string]*buffer.Buffer
	pathRequests      map[string]*common.PathRequest
	announceHistory   map[string]announceRecord
	announceHistoryMu sync.RWMutex
	identity          *identity.Identity
	destination       *destination.Destination

	// Node-specific information
	maxTransferSize int16 // Max transfer size in KB
	nodeEnabled     bool  // Whether this node is enabled
	nodeTimestamp   int64 // Last node announcement timestamp
}

type announceRecord struct {
	timestamp int64
	appData   []byte
}

func NewReticulum(cfg *common.ReticulumConfig) (*Reticulum, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Set default app name and aspect if not provided
	if cfg.AppName == "" {
		cfg.AppName = APP_NAME
	}
	if cfg.AppAspect == "" {
		cfg.AppAspect = APP_ASPECT // Always use "node" for node announcements
	}

	if err := initializeDirectories(); err != nil {
		return nil, fmt.Errorf("failed to initialize directories: %v", err)
	}
	debugLog(3, "Directories initialized")

	t := transport.NewTransport(cfg)
	debugLog(3, "Transport initialized")

	identity, err := identity.NewIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %v", err)
	}
	debugLog(2, "Created new identity: %x", identity.Hash())

	// Create destination
	debugLog(DEBUG_INFO, "Creating destination...")
	dest, err := destination.New(
		identity,
		destination.IN,
		destination.SINGLE,
		"nomadnetwork",
		t,
		"node",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination: %v", err)
	}
	debugLog(DEBUG_INFO, "Created destination with hash: %x", dest.GetHash())

	// Set node metadata
	nodeTimestamp := time.Now().Unix()

	r := &Reticulum{
		config:          cfg,
		transport:       t,
		interfaces:      make([]interfaces.Interface, 0),
		channels:        make(map[string]*channel.Channel),
		buffers:         make(map[string]*buffer.Buffer),
		pathRequests:    make(map[string]*common.PathRequest),
		announceHistory: make(map[string]announceRecord),
		identity:        identity,
		destination:     dest,

		// Node-specific information
		maxTransferSize: 500,  // Default 500KB
		nodeEnabled:     true, // Enabled by default
		nodeTimestamp:   nodeTimestamp,
	}

	// Enable destination features
	dest.AcceptsLinks(true)
	// Enable ratchets and point to a file for persistence.
	// The actual path should probably be configurable.
	ratchetPath := ".reticulum-go/storage/ratchets/" + r.identity.GetHexHash()
	dest.EnableRatchets(ratchetPath)
	dest.SetProofStrategy(destination.PROVE_APP)
	debugLog(DEBUG_VERBOSE, "Configured destination features")

	// Initialize interfaces from config
	for name, ifaceConfig := range cfg.Interfaces {
		if !ifaceConfig.Enabled {
			continue
		}

		var iface interfaces.Interface
		var err error

		switch ifaceConfig.Type {
		case "TCPClientInterface":
			iface, err = interfaces.NewTCPClientInterface(
				name,
				ifaceConfig.TargetHost,
				ifaceConfig.TargetPort,
				ifaceConfig.KISSFraming,
				ifaceConfig.I2PTunneled,
				ifaceConfig.Enabled,
			)
		case "UDPInterface":
			iface, err = interfaces.NewUDPInterface(
				name,
				ifaceConfig.Address,
				ifaceConfig.TargetHost,
				ifaceConfig.Enabled,
			)
		case "AutoInterface":
			iface, err = interfaces.NewAutoInterface(name, ifaceConfig)
		default:
			debugLog(1, "Unknown interface type: %s", ifaceConfig.Type)
			continue
		}

		if err != nil {
			if cfg.PanicOnInterfaceErr {
				return nil, fmt.Errorf("failed to create interface %s: %v", name, err)
			}
			debugLog(1, "Error creating interface %s: %v", name, err)
			continue
		}

		// Set packet callback
		iface.SetPacketCallback(func(data []byte, ni common.NetworkInterface) {
			debugLog(3, "Packet callback called for interface %s, data len: %d", ni.GetName(), len(data))
			if r.transport != nil {
				r.transport.HandlePacket(data, ni)
			} else {
				debugLog(1, "Transport is nil in packet callback")
			}
		})

		debugLog(2, "Configuring interface %s (type=%s)...", name, ifaceConfig.Type)
		r.interfaces = append(r.interfaces, iface)
		debugLog(3, "Interface %s started successfully", name)
	}

	return r, nil
}

func (r *Reticulum) handleInterface(iface common.NetworkInterface) {
	debugLog(DEBUG_INFO, "Setting up interface %s (type=%T)", iface.GetName(), iface)

	ch := channel.NewChannel(&transportWrapper{r.transport})
	r.channels[iface.GetName()] = ch

	rw := buffer.CreateBidirectionalBuffer(
		1,
		2,
		ch,
		func(size int) {
			data := make([]byte, size)
			debugLog(DEBUG_PACKETS, "Interface %s: Reading %d bytes from buffer", iface.GetName(), size)
			iface.ProcessIncoming(data)

			if len(data) > 0 {
				debugLog(DEBUG_TRACE, "Interface %s: Received packet type 0x%02x", iface.GetName(), data[0])
				r.transport.HandlePacket(data, iface)
			}
		},
	)

	r.buffers[iface.GetName()] = &buffer.Buffer{
		ReadWriter: rw,
	}
}

func (r *Reticulum) monitorInterfaces() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, iface := range r.interfaces {
			if tcpClient, ok := iface.(*interfaces.TCPClientInterface); ok {
				stats := fmt.Sprintf("Interface %s status - Connected: %v, TX: %d bytes (%.2f Kbps), RX: %d bytes (%.2f Kbps)",
					iface.GetName(),
					tcpClient.IsConnected(),
					tcpClient.GetTxBytes(),
					float64(tcpClient.GetTxBytes()*8)/(5*1024),
					tcpClient.GetRxBytes(),
					float64(tcpClient.GetRxBytes()*8)/(5*1024),
				)

				if runtime.GOOS != "windows" {
					stats = fmt.Sprintf("%s, RTT: %v", stats, tcpClient.GetRTT())
				}

				debugLog(DEBUG_VERBOSE, "%s", stats)
			}
		}
	}
}

func main() {
	flag.Parse()
	debugLog(1, "Initializing Reticulum (Debug Level: %d)...", *debugLevel)

	cfg, err := config.InitConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}
	debugLog(2, "Configuration loaded from: %s", cfg.ConfigPath)

	if len(cfg.Interfaces) == 0 {
		debugLog(2, "No interfaces configured, adding default interfaces")
		cfg.Interfaces = make(map[string]*common.InterfaceConfig)

		// Auto interface for local discovery
		cfg.Interfaces["Auto Discovery"] = &common.InterfaceConfig{
			Type:    "AutoInterface",
			Enabled: true,
			Name:    "Auto Discovery",
		}

		cfg.Interfaces["Go-RNS-Testnet"] = &common.InterfaceConfig{
			Type:       "TCPClientInterface",
			Enabled:    false,
			TargetHost: "127.0.0.1",
			TargetPort: 4242,
			Name:       "Go-RNS-Testnet",
		}

		cfg.Interfaces["Quad4 TCP"] = &common.InterfaceConfig{
			Type:       "TCPClientInterface",
			Enabled:    true,
			TargetHost: "rns.quad4.io",
			TargetPort: 4242,
			Name:       "Quad4 TCP",
		}
	}

	r, err := NewReticulum(cfg)
	if err != nil {
		log.Fatalf("Failed to create Reticulum instance: %v", err)
	}

	// Start monitoring interfaces
	go r.monitorInterfaces()

	// Register announce handler
	handler := NewAnnounceHandler(r, []string{"*"})
	r.transport.RegisterAnnounceHandler(handler)

	// Start Reticulum
	if err := r.Start(); err != nil {
		log.Fatalf("Failed to start Reticulum: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	debugLog(1, "Shutting down...")
	if err := r.Stop(); err != nil {
		debugLog(1, "Error during shutdown: %v", err)
	}
	debugLog(1, "Goodbye!")
}

type transportWrapper struct {
	*transport.Transport
}

func (tw *transportWrapper) GetRTT() float64 {
	return 0.1
}

func (tw *transportWrapper) RTT() float64 {
	return tw.GetRTT()
}

func (tw *transportWrapper) GetStatus() int {
	return transport.STATUS_ACTIVE
}

func (tw *transportWrapper) Send(data []byte) interface{} {
	p := &packet.Packet{
		PacketType: packet.PacketTypeData,
		Hops:       0,
		Data:       data,
		HeaderType: packet.HeaderType1,
	}

	err := tw.Transport.SendPacket(p)
	if err != nil {
		return nil
	}
	return p
}

func (tw *transportWrapper) Resend(p interface{}) error {
	if pkt, ok := p.(*packet.Packet); ok {
		return tw.Transport.SendPacket(pkt)
	}
	return fmt.Errorf("invalid packet type")
}

func (tw *transportWrapper) SetPacketTimeout(packet interface{}, callback func(interface{}), timeout time.Duration) {
	time.AfterFunc(timeout, func() {
		callback(packet)
	})
}

func (tw *transportWrapper) SetPacketDelivered(packet interface{}, callback func(interface{})) {
	callback(packet)
}

func initializeDirectories() error {
	dirs := []string{
		".reticulum-go",
		".reticulum-go/storage",
		".reticulum-go/storage/destinations",
		".reticulum-go/storage/identities",
		".reticulum-go/storage/ratchets",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil { // #nosec G301
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

func (r *Reticulum) Start() error {
	debugLog(2, "Starting Reticulum...")

	if err := r.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %v", err)
	}
	debugLog(3, "Transport started successfully")

	// Start interfaces
	for _, iface := range r.interfaces {
		debugLog(2, "Starting interface %s...", iface.GetName())
		if err := iface.Start(); err != nil {
			if r.config.PanicOnInterfaceErr {
				return fmt.Errorf("failed to start interface %s: %v", iface.GetName(), err)
			}
			debugLog(1, "Error starting interface %s: %v", iface.GetName(), err)
			continue
		}

		if netIface, ok := iface.(common.NetworkInterface); ok {
			// Register interface with transport
			if err := r.transport.RegisterInterface(iface.GetName(), netIface); err != nil {
				debugLog(1, "Failed to register interface %s with transport: %v", iface.GetName(), err)
			} else {
				debugLog(3, "Registered interface %s with transport", iface.GetName())
			}
			r.handleInterface(netIface)
		}
		debugLog(3, "Interface %s started successfully", iface.GetName())
	}

	// Wait for interfaces to initialize
	time.Sleep(2 * time.Second)

	// Send initial announce
	debugLog(2, "Sending initial announce")
	nodeName := "Go-Client"
	if err := r.destination.Announce([]byte(nodeName)); err != nil {
		debugLog(1, "Failed to send initial announce: %v", err)
	}

	// Start periodic announce goroutine
	go func() {
		// Wait a bit before the first announce
		time.Sleep(5 * time.Second)

		for {
			debugLog(3, "Announcing destination...")
			err := r.destination.Announce([]byte(nodeName))
			if err != nil {
				debugLog(1, "Could not send announce: %v", err)
			}

			time.Sleep(60 * time.Second)
		}
	}()

	go r.monitorInterfaces()

	debugLog(2, "Reticulum started successfully")
	return nil
}

func (r *Reticulum) Stop() error {
	debugLog(2, "Stopping Reticulum...")

	for _, buf := range r.buffers {
		if err := buf.Close(); err != nil {
			debugLog(1, "Error closing buffer: %v", err)
		}
	}

	for _, ch := range r.channels {
		if err := ch.Close(); err != nil {
			debugLog(1, "Error closing channel: %v", err)
		}
	}

	for _, iface := range r.interfaces {
		if err := iface.Stop(); err != nil {
			debugLog(1, "Error stopping interface %s: %v", iface.GetName(), err)
		}
	}

	if err := r.transport.Close(); err != nil {
		return fmt.Errorf("failed to close transport: %v", err)
	}

	debugLog(2, "Reticulum stopped successfully")
	return nil
}

type AnnounceHandler struct {
	aspectFilter []string
	reticulum    *Reticulum
}

func NewAnnounceHandler(r *Reticulum, aspectFilter []string) *AnnounceHandler {
	return &AnnounceHandler{
		aspectFilter: aspectFilter,
		reticulum:    r,
	}
}

func (h *AnnounceHandler) AspectFilter() []string {
	return h.aspectFilter
}

func (h *AnnounceHandler) ReceivedAnnounce(destHash []byte, id interface{}, appData []byte) error {
	debugLog(DEBUG_INFO, "Received announce from %x", destHash)
	debugLog(DEBUG_PACKETS, "Raw announce data: %x", appData)
	log.Printf("[DEBUG-3] MAIN HANDLER: Received announce from %x, appData len: %d", destHash, len(appData))

	var isNode bool
	var nodeEnabled bool
	var nodeTimestamp int64
	var nodeMaxSize int16

	// Parse msgpack appData from transport announce format
	if len(appData) > 0 {
		// appData is msgpack array [name, customData]
		if appData[0] == 0x92 { // array of 2 elements
			// Skip array header and first element (name)
			pos := 1
			if pos < len(appData) && appData[pos] == 0xc4 { // bin 8
				nameLen := int(appData[pos+1])
				pos += 2 + nameLen
				if pos < len(appData) && appData[pos] == 0xc4 { // bin 8
					dataLen := int(appData[pos+1])
					if pos+2+dataLen <= len(appData) {
						customData := appData[pos+2 : pos+2+dataLen]
						nodeName := string(customData)
						log.Printf("[DEBUG-3] Parsed node name: %s", nodeName)
						debugLog(DEBUG_INFO, "Announced node: %s", nodeName)
					}
				}
			}
		} else {
			// Fallback: treat as raw node name
			nodeName := string(appData)
			log.Printf("[DEBUG-3] Raw node name: %s", nodeName)
			debugLog(DEBUG_INFO, "Announced node: %s", nodeName)
		}
	} else {
		log.Printf("[DEBUG-3] No appData (empty announce)")
	}

	// Type assert and log identity details
	if identity, ok := id.(*identity.Identity); ok {
		debugLog(DEBUG_ALL, "Identity details:")
		debugLog(DEBUG_ALL, "  Hash: %s", identity.GetHexHash())
		debugLog(DEBUG_ALL, "  Public Key: %x", identity.GetPublicKey())

		ratchets := identity.GetRatchets()
		debugLog(DEBUG_ALL, "  Active Ratchets: %d", len(ratchets))

		if len(ratchets) > 0 {
			ratchetKey := identity.GetCurrentRatchetKey()
			if ratchetKey != nil {
				ratchetID := identity.GetRatchetID(ratchetKey)
				debugLog(DEBUG_ALL, "  Current Ratchet ID: %x", ratchetID)
			}
		}

		// Create a better record with more info
		recordType := "peer"
		if isNode {
			recordType = "node"
			debugLog(DEBUG_INFO, "Storing node in announce history: enabled=%v, timestamp=%d, maxsize=%dKB",
				nodeEnabled, nodeTimestamp, nodeMaxSize)
		}

		h.reticulum.announceHistoryMu.Lock()
		h.reticulum.announceHistory[identity.GetHexHash()] = announceRecord{
			timestamp: time.Now().Unix(),
			appData:   appData,
		}
		h.reticulum.announceHistoryMu.Unlock()

		debugLog(DEBUG_VERBOSE, "Stored %s announce in history for identity %s", recordType, identity.GetHexHash())
	}

	return nil
}

func (h *AnnounceHandler) ReceivePathResponses() bool {
	return true
}

func (r *Reticulum) GetDestination() *destination.Destination {
	return r.destination
}

func (r *Reticulum) createNodeAppData() []byte {
	// Create a msgpack array with 3 elements
	// [Bool, Int32, Int16] for [enable, timestamp, max_transfer_size]
	appData := []byte{0x93} // Array with 3 elements

	// Element 0: Boolean for enable/disable peer
	if r.nodeEnabled {
		appData = append(appData, 0xc3) // true
	} else {
		appData = append(appData, 0xc2) // false
	}

	// Element 1: Int32 timestamp (current time)
	// Update the timestamp when creating new announcements
	r.nodeTimestamp = time.Now().Unix()
	appData = append(appData, 0xd2) // int32 format
	timeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timeBytes, uint32(r.nodeTimestamp)) // #nosec G115
	appData = append(appData, timeBytes...)

	// Element 2: Int16 max transfer size in KB
	appData = append(appData, 0xd1) // int16 format
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(r.maxTransferSize)) // #nosec G115
	appData = append(appData, sizeBytes...)

	log.Printf("[DEBUG-7] Created node appData (msgpack [enable=%v, timestamp=%d, maxsize=%d]): %x",
		r.nodeEnabled, r.nodeTimestamp, r.maxTransferSize, appData)
	return appData
}
