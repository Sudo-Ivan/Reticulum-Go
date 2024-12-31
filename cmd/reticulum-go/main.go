package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

type Reticulum struct {
	config     *common.ReticulumConfig
	transport  *transport.Transport
	interfaces []interfaces.Interface
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
	}, nil
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

			callback := func(data []byte, ni common.NetworkInterface) {
				r.transport.HandlePacket(data, ni)
			}

			netIface.SetPacketCallback(callback)
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
