package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
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
	debugLevel = flag.Int("debug", 4, "Debug level (0-7)")
)

func debugLog(level int, format string, v ...interface{}) {
	if *debugLevel >= level {
		log.Printf("[DEBUG-%d] %s", level, fmt.Sprintf(format, v...))
	}
}

type Reticulum struct {
	config           *common.ReticulumConfig
	transport        *transport.Transport
	interfaces       []interfaces.Interface
	channels         map[string]*channel.Channel
	buffers          map[string]*buffer.Buffer
	announceHandlers map[string][]announce.AnnounceHandler
	pathRequests     map[string]*common.PathRequest
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

	return &Reticulum{
		config:           cfg,
		transport:        t,
		interfaces:       make([]interfaces.Interface, 0),
		channels:         make(map[string]*channel.Channel),
		buffers:          make(map[string]*buffer.Buffer),
		announceHandlers: make(map[string][]announce.AnnounceHandler),
		pathRequests:     make(map[string]*common.PathRequest),
	}, nil
}

func (r *Reticulum) handleInterface(iface common.NetworkInterface) {
	debugLog(2, "Setting up interface %s", iface.GetName())

	ch := channel.NewChannel(&transportWrapper{r.transport})
	r.channels[iface.GetName()] = ch
	debugLog(3, "Created channel for interface %s", iface.GetName())

	rw := buffer.CreateBidirectionalBuffer(
		1,
		2,
		ch,
		func(size int) {
			data := make([]byte, size)
			iface.ProcessIncoming(data)

			if len(data) > 0 && data[0] == announce.PACKET_TYPE_ANNOUNCE {
				r.handleAnnounce(data, iface)
			} else {
				r.transport.HandlePacket(data, iface)
			}

			debugLog(5, "Processed %d bytes from interface %s", size, iface.GetName())
		},
	)

	r.buffers[iface.GetName()] = &buffer.Buffer{
		ReadWriter: rw,
	}

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
				debugLog(4, "Interface %s status - Connected: %v, RTT: %v",
					iface.GetName(),
					tcpClient.IsConnected(),
					tcpClient.GetRTT(),
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

	go r.monitorInterfaces()

	// Register announce handler using the instance's transport
	handler := &AnnounceHandler{
		aspectFilter: []string{"*"}, // Handle all aspects
	}
	r.transport.RegisterAnnounceHandler(handler)

	// Create a destination to announce
	dest, err := identity.NewIdentity()
	if err != nil {
		log.Fatalf("Failed to create identity: %v", err)
	}

	// Create announce for the destination
	announce, err := announce.NewAnnounce(
		dest,
		[]byte("Reticulum-Go"), // App data
		nil,                    // No ratchet ID
		false,                  // Not a path response
	)
	if err != nil {
		log.Fatalf("Failed to create announce: %v", err)
	}

	// Send initial announce immediately
	for _, iface := range r.interfaces {
		if netIface, ok := iface.(common.NetworkInterface); ok {
			debugLog(2, "Sending initial announce on interface %s", netIface.GetName())
			if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
				debugLog(1, "Failed to propagate initial announce: %v", err)
			}
		}
	}

	// Then start periodic announces
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				for _, iface := range r.interfaces {
					if netIface, ok := iface.(common.NetworkInterface); ok {
						if err := announce.Propagate([]common.NetworkInterface{netIface}); err != nil {
							debugLog(1, "Failed to propagate announce: %v", err)
						}
					}
				}
			}
		}
	}()

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

	if err := r.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %v", err)
	}
	debugLog(3, "Transport started successfully")

	for name, ifaceConfig := range r.config.Interfaces {
		if !ifaceConfig.Enabled {
			debugLog(2, "Skipping disabled interface %s", name)
			continue
		}

		debugLog(2, "Configuring interface %s (type=%s)...", name, ifaceConfig.Type)
		var iface interfaces.Interface

		switch ifaceConfig.Type {
		case "TCPClientInterface":
			client, err := interfaces.NewTCPClientInterface(
				ifaceConfig.Name,
				ifaceConfig.TargetHost,
				ifaceConfig.TargetPort,
				ifaceConfig.KISSFraming,
				ifaceConfig.I2PTunneled,
				ifaceConfig.Enabled,
			)
			if err != nil {
				if r.config.PanicOnInterfaceErr {
					return fmt.Errorf("failed to create TCP client interface %s: %v", name, err)
				}
				debugLog(1, "Failed to create TCP client interface %s: %v", name, err)
				continue
			}
			iface = client

		case "TCPServerInterface":
			server, err := interfaces.NewTCPServerInterface(
				ifaceConfig.Name,
				ifaceConfig.Address,
				ifaceConfig.Port,
				ifaceConfig.KISSFraming,
				ifaceConfig.I2PTunneled,
				ifaceConfig.PreferIPv6,
			)
			if err != nil {
				if r.config.PanicOnInterfaceErr {
					return fmt.Errorf("failed to create TCP server interface %s: %v", name, err)
				}
				debugLog(1, "Failed to create TCP server interface %s: %v", name, err)
				continue
			}
			iface = server
		}

		if iface != nil {
			debugLog(2, "Starting interface %s...", name)
			if err := iface.Start(); err != nil {
				if r.config.PanicOnInterfaceErr {
					return fmt.Errorf("failed to start interface %s: %v", name, err)
				}
				debugLog(1, "Failed to start interface %s: %v", name, err)
				continue
			}

			netIface := iface.(common.NetworkInterface)
			r.handleInterface(netIface)
			r.interfaces = append(r.interfaces, iface)
			debugLog(3, "Interface %s started successfully", name)
		}
	}

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
	debugLog(3, "Successfully parsed announce packet")

	// Add random delay before propagation (0-2 seconds)
	delay := time.Duration(rand.Float64() * 2 * float64(time.Second))
	time.Sleep(delay)

	// Check interface modes and propagate according to RNS rules
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

		// Check if interface has bandwidth available for announces
		if netIface, ok := otherIface.(common.NetworkInterface); ok {
			if err := a.Propagate([]common.NetworkInterface{netIface}); err != nil {
				debugLog(1, "Error propagating announce: %v", err)
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
