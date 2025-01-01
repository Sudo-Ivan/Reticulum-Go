package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
	"github.com/Sudo-Ivan/reticulum-go/pkg/buffer"
	"github.com/Sudo-Ivan/reticulum-go/pkg/channel"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

var (
	debugLevel = flag.Int("debug", 7, "Debug level (0-7)")
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
	DEBUG_ALL             = 7    // Everything
)

type Reticulum struct {
	config            *common.ReticulumConfig
	transport         *transport.Transport
	interfaces        []interfaces.Interface
	channels          map[string]*channel.Channel
	buffers           map[string]*buffer.Buffer
	announceHandlers  map[string][]announce.AnnounceHandler
	pathRequests      map[string]*common.PathRequest
	announceHistory   map[string]announceRecord
	announceHistoryMu sync.RWMutex
}

type announceRecord struct {
	lastSeen   time.Time
	seenCount  int
	violations int
	interfaces map[string]bool
}

func NewReticulum(cfg *common.ReticulumConfig) (*Reticulum, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	if err := initializeDirectories(); err != nil {
		return nil, fmt.Errorf("failed to initialize directories: %v", err)
	}
	debugLog(3, "Directories initialized")

	t := transport.NewTransport(cfg)
	debugLog(3, "Transport initialized")

	r := &Reticulum{
		config:           cfg,
		transport:        t,
		interfaces:       make([]interfaces.Interface, 0),
		channels:         make(map[string]*channel.Channel),
		buffers:          make(map[string]*buffer.Buffer),
		announceHandlers: make(map[string][]announce.AnnounceHandler),
		pathRequests:     make(map[string]*common.PathRequest),
		announceHistory:  make(map[string]announceRecord),
	}

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
				ifaceConfig.Enabled,
				true, // IN
				true, // OUT
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

		debugLog(2, "Configuring interface %s (type=%s)...", name, ifaceConfig.Type)
		r.interfaces = append(r.interfaces, iface)
	}

	return r, nil
}

func (r *Reticulum) handleInterface(iface common.NetworkInterface) {
	debugLog(DEBUG_INFO, "Setting up interface %s (type=%T)", iface.GetName(), iface)

	ch := channel.NewChannel(&transportWrapper{r.transport})
	r.channels[iface.GetName()] = ch
	debugLog(DEBUG_VERBOSE, "Created channel for interface %s with transport wrapper", iface.GetName())

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
				if data[0] == announce.PACKET_TYPE_ANNOUNCE {
					r.handleAnnounce(data, iface)
				} else {
					r.transport.HandlePacket(data, iface)
				}
			}

			debugLog(5, "Processed %d bytes from interface %s", size, iface.GetName())
		},
	)

	r.buffers[iface.GetName()] = &buffer.Buffer{
		ReadWriter: rw,
	}
	debugLog(DEBUG_VERBOSE, "Created bidirectional buffer for interface %s", iface.GetName())

	iface.SetPacketCallback(func(data []byte, ni common.NetworkInterface) {
		if buf, ok := r.buffers[ni.GetName()]; ok {
			if _, err := buf.Write(data); err != nil {
				debugLog(1, "Error writing to buffer for interface %s: %v", ni.GetName(), err)
			}
			debugLog(6, "Written %d bytes to interface %s buffer", len(data), ni.GetName())
		}
		r.transport.HandlePacket(data, ni)
	})
}

func (r *Reticulum) monitorInterfaces() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, iface := range r.interfaces {
			if tcpClient, ok := iface.(*interfaces.TCPClientInterface); ok {
				debugLog(DEBUG_VERBOSE, "Interface %s status - Connected: %v, RTT: %v, TX: %d bytes (%.2f Kbps), RX: %d bytes (%.2f Kbps)",
					iface.GetName(),
					tcpClient.IsConnected(),
					tcpClient.GetRTT(),
					tcpClient.GetTxBytes(),
					float64(tcpClient.GetTxBytes()*8)/(5*1024), // Calculate Kbps over 5s interval
					tcpClient.GetRxBytes(),
					float64(tcpClient.GetRxBytes()*8)/(5*1024),
				)
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

	// Add default TCP interfaces if none configured
	if len(cfg.Interfaces) == 0 {
		debugLog(2, "No interfaces configured, adding default TCP interfaces")
		cfg.Interfaces = make(map[string]*common.InterfaceConfig)

		cfg.Interfaces["amsterdam"] = &common.InterfaceConfig{
			Type:       "TCPClientInterface",
			Enabled:    true,
			TargetHost: "amsterdam.connect.reticulum.network",
			TargetPort: 4965,
			Name:       "amsterdam",
		}

		cfg.Interfaces["btb"] = &common.InterfaceConfig{
			Type:       "TCPClientInterface",
			Enabled:    true,
			TargetHost: "reticulum.betweentheborders.com",
			TargetPort: 4242,
			Name:       "btb",
		}
	}

	r, err := NewReticulum(cfg)
	if err != nil {
		log.Fatalf("Failed to create Reticulum instance: %v", err)
	}

	// Create identity and destination
	identity, err := identity.NewIdentity()
	if err != nil {
		log.Fatalf("Failed to create identity: %v", err)
	}

	debugLog(2, "Created new identity: %x", identity.Hash())

	// Create announce
	announce, err := announce.NewAnnounce(
		identity,
		[]byte("nomadnetwork.node"),
		nil,   // No ratchet ID
		false, // Not a path response
	)
	if err != nil {
		log.Fatalf("Failed to create announce: %v", err)
	}

	// Start monitoring interfaces
	go r.monitorInterfaces()

	// Register announce handler
	handler := &AnnounceHandler{
		aspectFilter: []string{"*"},
	}
	r.transport.RegisterAnnounceHandler(handler)

	// Start Reticulum
	if err := r.Start(); err != nil {
		log.Fatalf("Failed to start Reticulum: %v", err)
	}

	// Send initial announces after interfaces are ready
	time.Sleep(2 * time.Second) // Give interfaces time to connect
	for _, iface := range r.interfaces {
		if netIface, ok := iface.(common.NetworkInterface); ok {
			if netIface.IsEnabled() && netIface.IsOnline() {
				debugLog(2, "Sending initial announce on interface %s", netIface.GetName())
				if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
					debugLog(1, "Failed to propagate initial announce: %v", err)
				}
			}
		}
	}

	// Start periodic announces
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			debugLog(3, "Starting periodic announce cycle")
			for _, iface := range r.interfaces {
				if netIface, ok := iface.(common.NetworkInterface); ok {
					if netIface.IsEnabled() && netIface.IsOnline() {
						debugLog(2, "Sending periodic announce on interface %s", netIface.GetName())
						if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
							debugLog(1, "Failed to propagate periodic announce: %v", err)
						}
					}
				}
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	debugLog(1, "Shutting down...")
	if err := r.Stop(); err != nil {
		debugLog(1, "Error during shutdown: %v", err)
	}
	debugLog(1, "Goodbye!")
}

// Update transportWrapper to use packet.Packet
type transportWrapper struct {
	*transport.Transport
}

func (tw *transportWrapper) GetRTT() float64 {
	return 0.1 // Default value for now
}

func (tw *transportWrapper) RTT() float64 {
	return tw.GetRTT()
}

func (tw *transportWrapper) GetStatus() int {
	return transport.STATUS_ACTIVE
}

func (tw *transportWrapper) Send(data []byte) interface{} {
	p := &packet.Packet{
		Header: [2]byte{
			packet.PacketTypeData, // First byte
			0,                     // Second byte (hops)
		},
		Data: data,
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
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

func (r *Reticulum) Start() error {
	debugLog(2, "Starting Reticulum...")

	// Create identity for announces
	identity, err := identity.NewIdentity()
	if err != nil {
		return fmt.Errorf("failed to create identity: %v", err)
	}
	debugLog(2, "Created new identity: %x", identity.Hash())

	// Create announce
	announce, err := announce.NewAnnounce(
		identity,
		[]byte("Reticulum-Go"),
		nil,   // No ratchet ID
		false, // Not a path response
	)
	if err != nil {
		return fmt.Errorf("failed to create announce: %v", err)
	}

	// Start transport
	if err := r.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %v", err)
	}
	debugLog(3, "Transport started successfully")

	// Start interfaces
	for _, iface := range r.interfaces {
		debugLog(2, "Starting interface %s...", iface.GetName())
		if err := iface.Start(); err != nil {
			return fmt.Errorf("failed to start interface %s: %v", iface.GetName(), err)
		}
		r.handleInterface(iface)
		debugLog(3, "Interface %s started successfully", iface.GetName())
	}

	// Wait for interfaces to be ready
	time.Sleep(2 * time.Second)

	// Send initial announces
	for _, iface := range r.interfaces {
		if netIface, ok := iface.(common.NetworkInterface); ok {
			if netIface.IsEnabled() && netIface.IsOnline() {
				debugLog(2, "Sending initial announce on interface %s", netIface.GetName())
				if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
					debugLog(1, "Failed to propagate initial announce: %v", err)
				}
			}
		}
	}

	// Start periodic announces
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			debugLog(3, "Starting periodic announce cycle")
			for _, iface := range r.interfaces {
				if netIface, ok := iface.(common.NetworkInterface); ok {
					if netIface.IsEnabled() && netIface.IsOnline() {
						debugLog(2, "Sending periodic announce on interface %s", netIface.GetName())
						if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
							debugLog(1, "Failed to propagate periodic announce: %v", err)
						}
					}
				}
			}
		}
	}()

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

func (r *Reticulum) handleAnnounce(data []byte, iface common.NetworkInterface) {
	debugLog(2, "Received announce packet on interface %s (%d bytes)", iface.GetName(), len(data))

	a := &announce.Announce{}
	if err := a.HandleAnnounce(data); err != nil {
		debugLog(1, "Error handling announce: %v", err)
		return
	}

	// Check announce history
	announceKey := fmt.Sprintf("%x", a.Hash())
	r.announceHistoryMu.Lock()
	record, exists := r.announceHistory[announceKey]

	if exists {
		// Check if this interface has already seen this announce
		if record.interfaces[iface.GetName()] {
			r.announceHistoryMu.Unlock()
			debugLog(4, "Duplicate announce from %s, ignoring", iface.GetName())
			return
		}

		// Check rate limiting
		timeSinceLastSeen := time.Since(record.lastSeen)
		if timeSinceLastSeen < time.Duration(ANNOUNCE_RATE_TARGET)*time.Second {
			if record.seenCount > ANNOUNCE_RATE_GRACE {
				record.violations++
				waitTime := ANNOUNCE_RATE_TARGET + (record.violations * ANNOUNCE_RATE_PENALTY)
				r.announceHistoryMu.Unlock()
				debugLog(3, "Rate limit exceeded for announce %s, waiting %d seconds", announceKey, waitTime)
				return
			}
		}

		record.seenCount++
		record.lastSeen = time.Now()
		record.interfaces[iface.GetName()] = true
	} else {
		record = announceRecord{
			lastSeen:   time.Now(),
			seenCount:  1,
			interfaces: make(map[string]bool),
		}
		record.interfaces[iface.GetName()] = true
		r.announceHistory[announceKey] = record
	}
	r.announceHistoryMu.Unlock()

	// Add random delay before propagation (0-2 seconds)
	delay := time.Duration(rand.Float64() * 2 * float64(time.Second))
	time.Sleep(delay)

	// Propagate to other interfaces according to RNS rules
	for _, otherIface := range r.interfaces {
		if otherIface.GetName() == iface.GetName() {
			continue
		}

		srcMode := iface.GetMode()
		dstMode := otherIface.GetMode()

		// Skip propagation based on interface modes
		if srcMode == common.IF_MODE_ACCESS_POINT && dstMode != common.IF_MODE_FULL {
			debugLog(4, "Skipping announce propagation from AP to non-full mode interface")
			continue
		}
		if srcMode == common.IF_MODE_ROAMING && dstMode == common.IF_MODE_ACCESS_POINT {
			debugLog(4, "Skipping announce propagation from roaming to AP interface")
			continue
		}

		// Check if interface has bandwidth available
		if netIface, ok := otherIface.(common.NetworkInterface); ok {
			if netIface.GetBandwidthAvailable() {
				if err := a.Propagate([]common.NetworkInterface{netIface}); err != nil {
					debugLog(1, "Error propagating announce: %v", err)
				}
			} else {
				debugLog(3, "Interface %s has insufficient bandwidth for announce", netIface.GetName())
			}
		}
	}
}

type AnnounceHandler struct {
	aspectFilter []string
}

func (h *AnnounceHandler) AspectFilter() []string {
	return h.aspectFilter
}

func (h *AnnounceHandler) ReceivedAnnounce(destHash []byte, identity interface{}, appData []byte) error {
	debugLog(3, "Received announce from %x", destHash)

	if len(appData) > 0 {
		debugLog(3, "Announce contained app data: %s", string(appData))
	}

	if id, ok := identity.([]byte); ok {
		debugLog(4, "Identity: %x", id)
	}

	return nil
}

func (h *AnnounceHandler) ReceivePathResponses() bool {
	return true
}
