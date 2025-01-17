package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"log/slog"
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
	debugLevel       = flag.Int("debug", int(slog.LevelDebug*2), "Debug level (-8 - 8)")
	interceptPackets = flag.Bool("intercept-packets", false, "Enable packet interception")
	interceptOutput  = flag.String("intercept-output", "packets.log", "Output file for intercepted packets")
)

const (
	ANNOUNCE_RATE_TARGET  = 3600 // Default target time between announces (1 hour)
	ANNOUNCE_RATE_GRACE   = 3    // Number of grace announces before enforcing rate
	ANNOUNCE_RATE_PENALTY = 7200 // Additional penalty time for rate violations
	MAX_ANNOUNCE_HOPS     = 128  // Maximum number of hops for announces
	APP_NAME              = "Go Client"
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
	slog.Info("Directories initialized")

	t := transport.NewTransport(cfg)
	slog.Info("Transport initialized")

	identity, err := identity.NewIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %v", err)
	}
	slog.Info("Created new identity", "hash", hex.EncodeToString(identity.Hash()))

	// Create destination
	slog.Info("Creating destination...")
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
	slog.Info("Created destination", "hash", hex.EncodeToString(dest.GetHash()))

	// Enable destination features
	dest.AcceptsLinks(true)
	dest.EnableRatchets("") // Empty string for default path
	dest.SetProofStrategy(destination.PROVE_APP)
	slog.Debug("Configured destination features")

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
			slog.Error("Failed to initialize packet interceptor", "err", err)
		} else {
			slog.Info("Packet interception enabled")
		}
	}

	// Create a wrapper for the packet callback that includes interception
	packetCallbackWrapper := func(data []byte, iface common.NetworkInterface) {
		if interceptor != nil {
			if err := interceptor.InterceptIncoming(data, iface); err != nil {
				slog.Error("Failed to intercept incoming packet", "err", err)
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
			slog.Error("Unknown interface type", "type", ifaceConfig.Type)
			continue
		}

		if err != nil {
			if cfg.PanicOnInterfaceErr {
				return nil, fmt.Errorf("failed to create interface %s: %v", name, err)
			}
			slog.Error("Error creating interface", "interface", name, "err", err)
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
		slog.Info("Configuring interface", "interface", name, "type", ifaceConfig.Type)
		r.interfaces = append(r.interfaces, iface)
		slog.Info("Interface started successfully", "interface", name)
	}

	return r, nil
}

func (r *Reticulum) handleInterface(iface common.NetworkInterface) {
	slog.Info("Setting up interface", "interface", iface.GetName(), "type", fmt.Sprintf("%T", iface))

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
			slog.Debug("Reading from buffer", "interface", iface.GetName(), "bytes", size)
			iface.ProcessIncoming(data)

			if len(data) > 0 {
				// Intercept incoming packet before processing
				if interceptor != nil {
					if err := interceptor.InterceptIncoming(data, iface); err != nil {
						slog.Error("Failed to intercept incoming packet", "err", err)
					}
				}
				slog.Log(context.Background(), slog.LevelDebug*2, "Received packet",
					"interface", iface.GetName(), "type", fmt.Sprintf("0x%02x", data[0]))
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
				slog.Debug("Status",
					"interface", iface.GetName(),
					"connected", tcpClient.IsConnected(),
					"RTT", tcpClient.GetRTT(),
					"TX", tcpClient.GetTxBytes(),
					"TX Kbps", fmt.Sprintf("%.2f", float64(tcpClient.GetTxBytes()*8)/(5*1024)), // Calculate Kbps over 5s interval
					"RX", tcpClient.GetRxBytes(),
					"RX Kbps", fmt.Sprintf("%.2f", float64(tcpClient.GetRxBytes()*8)/(5*1024)), // Calculate Kbps over 5s interval
				)
			}
		}
	}
}

func main() {
	flag.Parse()
	slog.Info("Initializing Reticulum...", "debug level", *debugLevel)
	slog.SetLogLoggerLevel(slog.Level(*debugLevel))

	cfg, err := config.InitConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}
	slog.Info("Configuration loaded", "source", cfg.ConfigPath)

	// Add default TCP interfaces if none configured
	if len(cfg.Interfaces) == 0 {
		slog.Warn("No interfaces configured, adding default TCP interfaces")
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
				slog.Info("Sending initial announce", "interface", netIface.GetName())
				if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
					slog.Error("Failed to propagate initial announce", "err", err)
				}
			}
		}
	}

	// Start periodic announces
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			slog.Info("Starting periodic announce cycle")
			for _, iface := range r.interfaces {
				if netIface, ok := iface.(common.NetworkInterface); ok {
					if netIface.IsEnabled() && netIface.IsOnline() {
						slog.Info("Sending periodic announce", "interface", netIface.GetName())
						if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
							slog.Error("Failed to propagate periodic announce", "err", err)
						}
					}
				}
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutting down...")
	if err := r.Stop(); err != nil {
		slog.Error("Error during shutdown", "err", err)
	}
	slog.Info("Goodbye!")
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
	slog.Info("Starting Reticulum...")

	// Start transport first
	if err := r.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %v", err)
	}
	slog.Info("Transport started successfully")

	// Start interfaces and set up handlers
	for _, iface := range r.interfaces {
		slog.Info("Starting interface", "interface", iface.GetName())
		if err := iface.Start(); err != nil {
			if r.config.PanicOnInterfaceErr {
				return fmt.Errorf("failed to start interface %s: %v", iface.GetName(), err)
			}
			slog.Error("Error starting interface", "interface", iface.GetName(), "err", err)
			continue
		}

		if netIface, ok := iface.(common.NetworkInterface); ok {
			r.handleInterface(netIface)
		}
		slog.Info("Interface started successfully", "interface", iface.GetName())
	}

	// Create initial announce
	initialAnnounce, err := announce.NewAnnounce(
		r.identity,
		[]byte("Reticulum-Go"),
		nil,   // ratchetID
		false, // pathResponse
		r.config,
	)
	if err != nil {
		return fmt.Errorf("failed to create announce: %v", err)
	}

	// Wait briefly for interfaces to initialize
	time.Sleep(2 * time.Second)

	// Send initial announces
	for _, iface := range r.interfaces {
		if netIface, ok := iface.(common.NetworkInterface); ok {
			if netIface.IsEnabled() && netIface.IsOnline() {
				slog.Info("Sending initial announce", "interface", netIface.GetName())
				if err := initialAnnounce.Propagate([]common.NetworkInterface{netIface}); err != nil {
					slog.Error("Failed to send initial announce", "interface", netIface.GetName(), "err", err)
				}
			}
		}
	}

	// Start periodic announce goroutine
	go func() {
		ticker := time.NewTicker(ANNOUNCE_RATE_TARGET * time.Second)
		defer ticker.Stop()

		announceCount := 0
		for range ticker.C {
			announceCount++
			slog.Info("Starting periodic announce cycle", "count", announceCount)
			// Create fresh announce for each cycle
			periodicAnnounce, err := announce.NewAnnounce(
				r.identity,
				[]byte("Reticulum-Go"),
				nil,   // ratchetID
				false, // pathResponse
				r.config,
			)
			if err != nil {
				slog.Error("Failed to create periodic announce", "err", err)
				continue
			}

			for _, iface := range r.interfaces {
				if netIface, ok := iface.(common.NetworkInterface); ok {
					if netIface.IsEnabled() && netIface.IsOnline() {
						slog.Info("Sending periodic announce", "interface", netIface.GetName())
						if err := periodicAnnounce.Propagate([]common.NetworkInterface{netIface}); err != nil {
							slog.Error("Failed to send periodic announce", "interface", "err", err)

							continue
						}

						// Apply rate limiting after grace period
						if announceCount > ANNOUNCE_RATE_GRACE {
							time.Sleep(time.Duration(ANNOUNCE_RATE_PENALTY) * time.Second)
						}
					}
				}
			}
		}
	}()

	// Start interface monitoring
	go r.monitorInterfaces()

	slog.Info("Reticulum started successfully")
	return nil
}

func (r *Reticulum) Stop() error {
	slog.Info("Stopping Reticulum...")

	for _, buf := range r.buffers {
		if err := buf.Close(); err != nil {
			slog.Error("Error closing buffer", "err", err)
		}
	}

	for _, ch := range r.channels {
		if err := ch.Close(); err != nil {
			slog.Error("Error closing channel", "err", err)
		}
	}

	for _, iface := range r.interfaces {
		if err := iface.Stop(); err != nil {
			slog.Error("Error stopping interface", "interface", iface.GetName(), "err", err)
		}
	}

	if err := r.transport.Close(); err != nil {
		return fmt.Errorf("failed to close transport: %v", err)
	}

	slog.Info("Reticulum stopped successfully")
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
	slog.Info("Received announce", "hash", hex.EncodeToString(destHash))
	slog.Debug("Raw announce data", "data", hex.EncodeToString(appData))

	// Parse msgpack array
	if len(appData) > 0 {
		if appData[0] == 0x92 { // msgpack array of 2 elements
			var pos = 1

			// Parse first element (name)
			if appData[pos] == 0xc4 { // bin 8 format
				nameLen := int(appData[pos+1])
				name := string(appData[pos+2 : pos+2+nameLen])
				pos += 2 + nameLen
				// Parse second element (app data)
				if pos < len(appData) && appData[pos] == 0xc4 { // bin 8 format
					dataLen := int(appData[pos+1])
					data := appData[pos+2 : pos+2+dataLen]
					slog.Debug("Announce", "name", name, "app data", string(data))
				} else {
					slog.Debug("Announce", "name", name)
				}
			}
		}
	}

	// Type assert and log identity details
	if identity, ok := id.(*identity.Identity); ok {
		ratchets := identity.GetRatchets()

		slog.Log(context.Background(), slog.LevelDebug*2, "Identity details",
			"hash", identity.GetHexHash(),
			"pubkey", hex.EncodeToString(identity.GetPublicKey()),
			"active ratchets", len(ratchets))

		if len(ratchets) > 0 {
			ratchetKey := identity.GetCurrentRatchetKey()
			if ratchetKey != nil {
				slog.Log(context.Background(), slog.LevelDebug*2,
					"Current Ratchet", "id", identity.GetRatchetID(ratchetKey))
			}
		}

		// Store announce in history
		h.reticulum.announceHistoryMu.Lock()
		h.reticulum.announceHistory[identity.GetHexHash()] = announceRecord{
			// You can add fields here to store relevant announce data
		}
		h.reticulum.announceHistoryMu.Unlock()
		slog.Debug("Stored announce in history", "identity", identity.GetHexHash())
	}

	return nil
}

func (h *AnnounceHandler) ReceivePathResponses() bool {
	return true
}

func (r *Reticulum) GetDestination() *destination.Destination {
	return r.destination
}
