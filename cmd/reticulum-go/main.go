package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/buffer"
	"github.com/Sudo-Ivan/reticulum-go/pkg/channel"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

type Reticulum struct {
	config     *common.ReticulumConfig
	transport  *transport.Transport
	interfaces []interfaces.Interface
	channels   map[string]*channel.Channel
	buffers    map[string]*buffer.Buffer
}

func NewReticulum(cfg *common.ReticulumConfig) (*Reticulum, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	t, err := transport.NewTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transport: %v", err)
	}

	return &Reticulum{
		config:     cfg,
		transport:  t,
		interfaces: make([]interfaces.Interface, 0),
		channels:   make(map[string]*channel.Channel),
		buffers:    make(map[string]*buffer.Buffer),
	}, nil
}

func (r *Reticulum) handleInterface(iface common.NetworkInterface) {
	// Create channel using transport wrapper
	ch := channel.NewChannel(&transportWrapper{r.transport})
	r.channels[iface.GetName()] = ch

	// Create bidirectional buffer
	rw := buffer.CreateBidirectionalBuffer(
		1, // Receive stream ID
		2, // Send stream ID
		ch,
		func(size int) {
			// Handle data ready callback
			data := make([]byte, size)
			iface.ProcessIncoming(data)
			r.transport.HandlePacket(data, iface)
		},
	)

	// Store the buffer
	r.buffers[iface.GetName()] = &buffer.Buffer{
		ReadWriter: rw,
	}

	// Set up packet callback
	iface.SetPacketCallback(func(data []byte, ni common.NetworkInterface) {
		if buf, ok := r.buffers[ni.GetName()]; ok {
			if _, err := buf.Write(data); err != nil {
				log.Printf("Error writing to buffer for interface %s: %v", ni.GetName(), err)
			}
		}
		r.transport.HandlePacket(data, ni)
	})
}

func (r *Reticulum) Start() error {
	log.Printf("Starting Reticulum...")

	if err := r.transport.Start(); err != nil {
		return fmt.Errorf("failed to start transport: %v", err)
	}
	log.Printf("Transport started successfully")

	for name, ifaceConfig := range r.config.Interfaces {
		if !ifaceConfig.Enabled {
			log.Printf("Skipping disabled interface %s", name)
			continue
		}

		log.Printf("Configuring interface %s (type=%s)...", name, ifaceConfig.Type)
		var iface interfaces.Interface

		switch ifaceConfig.Type {
		case "TCPClientInterface":
			log.Printf("Creating TCP client interface %s -> %s:%d", name, ifaceConfig.TargetHost, ifaceConfig.TargetPort)
			client, err := interfaces.NewTCPClient(
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
				log.Printf("Failed to create TCP client interface %s: %v", name, err)
				continue
			}
			iface = client

		case "TCPServerInterface":
			log.Printf("Creating TCP server interface %s on %s:%d", name, ifaceConfig.Address, ifaceConfig.Port)
			server, err := interfaces.NewTCPServer(
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
				log.Printf("Failed to create TCP server interface %s: %v", name, err)
				continue
			}
			iface = server

		case "UDPInterface":
			addr := fmt.Sprintf("%s:%d", ifaceConfig.Address, ifaceConfig.Port)
			target := ""
			if ifaceConfig.TargetAddress != "" {
				target = fmt.Sprintf("%s:%d", ifaceConfig.TargetHost, ifaceConfig.TargetPort)
			}
			log.Printf("Creating UDP interface %s on %s -> %s", name, addr, target)
			udp, err := interfaces.NewUDPInterface(
				ifaceConfig.Name,
				addr,
				target,
				ifaceConfig.Enabled,
			)
			if err != nil {
				if r.config.PanicOnInterfaceErr {
					return fmt.Errorf("failed to create UDP interface %s: %v", name, err)
				}
				log.Printf("Failed to create UDP interface %s: %v", name, err)
				continue
			}
			iface = udp

		case "AutoInterface":
			log.Printf("Creating Auto interface %s (group=%s, discovery=%d, data=%d)",
				name, ifaceConfig.GroupID, ifaceConfig.DiscoveryPort, ifaceConfig.DataPort)
			auto, err := interfaces.NewAutoInterface(
				ifaceConfig.Name,
				ifaceConfig,
			)
			if err != nil {
				if r.config.PanicOnInterfaceErr {
					return fmt.Errorf("failed to create Auto interface %s: %v", name, err)
				}
				log.Printf("Failed to create Auto interface %s: %v", name, err)
				continue
			}
			iface = auto

		default:
			log.Printf("Unknown interface type: %s", ifaceConfig.Type)
			continue
		}

		if iface != nil {
			log.Printf("Starting interface %s...", name)
			if err := iface.Start(); err != nil {
				if r.config.PanicOnInterfaceErr {
					return fmt.Errorf("failed to start interface %s: %v", name, err)
				}
				log.Printf("Failed to start interface %s: %v", name, err)
				continue
			}

			netIface := iface.(common.NetworkInterface)
			r.handleInterface(netIface)
			r.interfaces = append(r.interfaces, iface)
			log.Printf("Created and started interface %s (type=%v, enabled=%v)",
				iface.GetName(), iface.GetType(), iface.IsEnabled())
			log.Printf("Interface %s started successfully", name)
		}
	}

	log.Printf("Reticulum initialized with config at: %s", r.config.ConfigPath)
	log.Printf("Press Ctrl+C to stop...")
	return nil
}

func (r *Reticulum) Stop() error {
	// Close all buffers
	for _, buf := range r.buffers {
		if err := buf.Close(); err != nil {
			log.Printf("Error closing buffer: %v", err)
		}
	}

	// Close all channels
	for _, ch := range r.channels {
		if err := ch.Close(); err != nil {
			log.Printf("Error closing channel: %v", err)
		}
	}

	// Stop interfaces
	for _, iface := range r.interfaces {
		if err := iface.Stop(); err != nil {
			log.Printf("Error stopping interface %s: %v", iface.GetName(), err)
		}
	}

	if err := r.transport.Close(); err != nil {
		return fmt.Errorf("failed to close transport: %v", err)
	}
	return nil
}

func main() {
	log.Printf("Initializing Reticulum...")

	cfg, err := config.InitConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	r, err := NewReticulum(cfg)
	if err != nil {
		log.Fatalf("Failed to create Reticulum instance: %v", err)
	}

	if err := r.Start(); err != nil {
		log.Fatalf("Failed to start Reticulum: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("\nShutting down...")
	if err := r.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
	log.Printf("Goodbye!")
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
