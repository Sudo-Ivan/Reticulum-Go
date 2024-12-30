package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
)

type Reticulum struct {
	config    *common.ReticulumConfig
	transport *transport.Transport
	interfaces []interfaces.Interface
}

func NewReticulum(cfg *common.ReticulumConfig) (*Reticulum, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Initialize transport
	t, err := transport.NewTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &Reticulum{
		config:    cfg,
		transport: t,
	}, nil
}

func (r *Reticulum) Start() error {
	for _, ifaceConfig := range r.config.Interfaces {
		var iface interfaces.Interface

		switch ifaceConfig.Type {
		case "TCPClientInterface":
			client, err := interfaces.NewTCPClient(
				ifaceConfig.Name,
				ifaceConfig.TargetHost,
				ifaceConfig.TargetPort,
				ifaceConfig.KISSFraming,
				ifaceConfig.I2PTunneled,
			)
			if err != nil {
				log.Printf("Failed to create TCP interface %s: %v", ifaceConfig.Name, err)
				continue
			}
			iface = client

		case "TCPServerInterface":
			server, err := interfaces.NewTCPServer(
				ifaceConfig.Name,
				ifaceConfig.Address,
				ifaceConfig.Port,
				ifaceConfig.PreferIPv6,
				ifaceConfig.I2PTunneled,
			)
			if err != nil {
				log.Printf("Failed to create TCP server interface %s: %v", ifaceConfig.Name, err)
				continue
			}
			iface = server

		case "UDPInterface":
			addr := fmt.Sprintf("%s:%d", ifaceConfig.Address, ifaceConfig.Port)
			udp, err := interfaces.NewUDPInterface(
				ifaceConfig.Name,
				addr,
				"", // No target address for server initially
			)
			if err != nil {
				log.Printf("Failed to create UDP interface %s: %v", ifaceConfig.Name, err)
				continue
			}
			iface = udp

		case "AutoInterface":
			log.Printf("AutoInterface type not yet implemented")
			continue

		default:
			log.Printf("Unknown interface type: %s", ifaceConfig.Type)
			continue
		}

		if iface != nil {
			// Set packet callback to transport
			iface.SetPacketCallback(r.transport.HandlePacket)
			r.interfaces = append(r.interfaces, iface)
		}
	}

	log.Printf("Reticulum initialized with config at: %s", r.config.ConfigPath)
	return nil
}

func (r *Reticulum) Stop() error {
	if err := r.transport.Close(); err != nil {
		return err
	}
	return nil
}

func main() {
	// Initialize configuration
	cfg, err := config.InitConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	// Create new reticulum instance
	r, err := NewReticulum(cfg)
	if err != nil {
		log.Fatalf("Failed to create Reticulum instance: %v", err)
	}

	// Start reticulum
	if err := r.Start(); err != nil {
		log.Fatalf("Failed to start Reticulum: %v", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Clean shutdown
	if err := r.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
} 