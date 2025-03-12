package main

import (
	"flag"
	"fmt"
	"log"
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
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	testutils "github.com/Sudo-Ivan/reticulum-go/test-utilities"
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
	APP_ASPECT            = "node"
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
}

type announceRecord struct {
}

func NewReticulum(cfg *common.ReticulumConfig) (*Reticulum, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Set default app name and aspect if not provided
	if cfg.AppName == "" {
		cfg.AppName = "Go Client"
	}
	if cfg.AppAspect == "" {
		cfg.AppAspect = "node"
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
		APP_NAME,
		APP_ASPECT,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination: %v", err)
	}
	debugLog(DEBUG_INFO, "Created destination with hash: %x", dest.GetHash())

	// Set default app data for announces
	appData := []byte(fmt.Sprintf(`{"app":"%s","aspect":"%s","version":"0.1.0"}`, APP_NAME, APP_ASPECT))
	dest.SetDefaultAppData(appData)

	// Enable destination features
	dest.AcceptsLinks(true)
	dest.EnableRatchets("") // Empty string for default path
	dest.SetProofStrategy(destination.PROVE_APP)
	debugLog(DEBUG_VERBOSE, "Configured destination features")

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
	}

	// Initialize packet interceptor if enabled
	var interceptor *testutils.PacketInterceptor
	if *interceptPackets {
		var err error
		interceptor, err = testutils.NewPacketInterceptor(*interceptOutput)
		if err != nil {
			debugLog(DEBUG_ERROR, "Failed to initialize packet interceptor: %v", err)
		} else {
			debugLog(DEBUG_INFO, "Packet interception enabled")
		}
	}

	// Create a wrapper for the packet callback that includes interception
	packetCallbackWrapper := func(data []byte, iface common.NetworkInterface) {
		if interceptor != nil {
			if err := interceptor.InterceptIncoming(data, iface); err != nil {
				debugLog(DEBUG_ERROR, "Failed to intercept incoming packet: %v", err)
			}
		}
		// Call original callback
		if r.transport != nil {
			r.transport.HandlePacket(data, iface)
		}
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

		// Set the wrapped packet callback
		iface.SetPacketCallback(packetCallbackWrapper)

		// Wrap interface for outgoing packet interception
		if interceptor != nil {
			iface = interfaces.NewInterceptedInterface(iface, func(data []byte, ni common.NetworkInterface) error {
				return interceptor.InterceptOutgoing(data, ni)
			})
		}

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

	// Get interceptor if enabled
	var interceptor *testutils.PacketInterceptor
	if *interceptPackets {
		interceptor, _ = testutils.NewPacketInterceptor(*interceptOutput)
	}

	rw := buffer.CreateBidirectionalBuffer(
		1,
		2,
		ch,
		func(size int) {
			data := make([]byte, size)
			debugLog(DEBUG_PACKETS, "Interface %s: Reading %d bytes from buffer", iface.GetName(), size)
			iface.ProcessIncoming(data)

			if len(data) > 0 {
				// Intercept incoming packet before processing
				if interceptor != nil {
					if err := interceptor.InterceptIncoming(data, iface); err != nil {
						debugLog(DEBUG_ERROR, "Failed to intercept incoming packet: %v", err)
					}
				}

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

		cfg.Interfaces["Go-RNS-Testnet"] = &common.InterfaceConfig{
			Type:       "TCPClientInterface",
			Enabled:    true,
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

	// Create announce using r.identity
	announce, err := announce.NewAnnounce(
		r.identity,
		[]byte("HELLO WORLD"),
		nil,
		false,
		r.config,
	)
	if err != nil {
		log.Fatalf("Failed to create announce: %v", err)
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
		if err := os.MkdirAll(dir, 0755); err != nil {
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
			r.handleInterface(netIface)
		}
		debugLog(3, "Interface %s started successfully", iface.GetName())
	}

	// Wait for interfaces to initialize
	time.Sleep(2 * time.Second)

	// Send initial announce once per interface
	initialAnnounce, err := announce.NewAnnounce(
		r.identity,
		createAppData(r.config.AppName, r.config.AppAspect),
		nil,
		false,
		r.config,
	)
	if err != nil {
		return fmt.Errorf("failed to create announce: %v", err)
	}

	for _, iface := range r.interfaces {
		if netIface, ok := iface.(common.NetworkInterface); ok {
			if netIface.IsEnabled() && netIface.IsOnline() {
				debugLog(2, "Sending initial announce on interface %s", netIface.GetName())
				if err := initialAnnounce.Propagate([]common.NetworkInterface{netIface}); err != nil {
					debugLog(1, "Failed to send initial announce on interface %s: %v", netIface.GetName(), err)
				}
				// Add delay between interfaces
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	// Start periodic announce goroutine with rate limiting
	go func() {
		ticker := time.NewTicker(ANNOUNCE_RATE_TARGET * time.Second)
		defer ticker.Stop()

		announceCount := 0
		for range ticker.C {
			announceCount++
			debugLog(3, "Starting periodic announce cycle #%d", announceCount)

			periodicAnnounce, err := announce.NewAnnounce(
				r.identity,
				createAppData(r.config.AppName, r.config.AppAspect),
				nil,
				false,
				r.config,
			)
			if err != nil {
				debugLog(1, "Failed to create periodic announce: %v", err)
				continue
			}

			// Send to each interface with rate limiting
			for _, iface := range r.interfaces {
				if netIface, ok := iface.(common.NetworkInterface); ok {
					if netIface.IsEnabled() && netIface.IsOnline() {
						// Apply rate limiting after grace period
						if announceCount > ANNOUNCE_RATE_GRACE {
							time.Sleep(time.Duration(ANNOUNCE_RATE_PENALTY) * time.Second)
						}

						debugLog(2, "Sending periodic announce on interface %s", netIface.GetName())
						if err := periodicAnnounce.Propagate([]common.NetworkInterface{netIface}); err != nil {
							debugLog(1, "Failed to send periodic announce on interface %s: %v", netIface.GetName(), err)
							continue
						}
					}
				}
			}
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

	// Parse msgpack array
	if len(appData) > 0 {
		if appData[0] == 0x92 { // msgpack array of 2 elements
			var pos = 1

			// Parse first element (name)
			if appData[pos] == 0xc4 { // bin 8 format
				nameLen := int(appData[pos+1])
				name := string(appData[pos+2 : pos+2+nameLen])
				pos += 2 + nameLen
				debugLog(DEBUG_VERBOSE, "Announce name: %s", name)

				// Parse second element (app data)
				if pos < len(appData) && appData[pos] == 0xc4 { // bin 8 format
					dataLen := int(appData[pos+1])
					data := appData[pos+2 : pos+2+dataLen]
					debugLog(DEBUG_VERBOSE, "Announce app data: %s", string(data))
				}
			}
		}
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

		// Store announce in history
		h.reticulum.announceHistoryMu.Lock()
		h.reticulum.announceHistory[identity.GetHexHash()] = announceRecord{
			// You can add fields here to store relevant announce data
		}
		h.reticulum.announceHistoryMu.Unlock()

		debugLog(DEBUG_VERBOSE, "Stored announce in history for identity %s", identity.GetHexHash())
	}

	return nil
}

func (h *AnnounceHandler) ReceivePathResponses() bool {
	return true
}

func (r *Reticulum) GetDestination() *destination.Destination {
	return r.destination
}

func createAppData(appName, appAspect string) []byte {
	nameString := fmt.Sprintf("%s.%s", appName, appAspect)

	// Create MessagePack array with 2 elements
	appData := []byte{0x92} // Fix array with 2 elements

	// First element: name string (always use str 8 format for consistency)
	nameBytes := []byte(nameString)
	appData = append(appData, 0xd9)                 // str 8 format
	appData = append(appData, byte(len(nameBytes))) // length
	appData = append(appData, nameBytes...)         // string data

	// Second element: version string (always use str 8 format for consistency)
	version := "0.1.0"
	versionBytes := []byte(version)
	appData = append(appData, 0xd9)                    // str 8 format
	appData = append(appData, byte(len(versionBytes))) // length
	appData = append(appData, versionBytes...)         // string data

	return appData
}
