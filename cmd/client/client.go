package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
)

var (
	configPath = flag.String("config", "", "Path to config file")
	targetHash = flag.String("target", "", "Target destination hash")
	generateIdentity = flag.Bool("generate-identity", false, "Generate a new identity and print its hash")
)

type Client struct {
	config     *common.ReticulumConfig
	transport  *transport.Transport
	interfaces []common.NetworkInterface
}

func NewClient(cfg *common.ReticulumConfig) (*Client, error) {
	if cfg == nil {
		var err error
		cfg, err = config.InitConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize config: %v", err)
		}
	}

	t, err := transport.NewTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transport: %v", err)
	}

	return &Client{
		config:     cfg,
		transport:  t,
		interfaces: make([]common.NetworkInterface, 0),
	}, nil
}

func (c *Client) Start() error {
	for _, ifaceConfig := range c.config.Interfaces {
		var iface common.NetworkInterface

		switch ifaceConfig.Type {
		case "tcp":
			client, err := interfaces.NewTCPClient(
				ifaceConfig.Name,
				ifaceConfig.Address,
				ifaceConfig.Port,
				ifaceConfig.KISSFraming,
				ifaceConfig.I2PTunneled,
			)
			if err != nil {
				log.Printf("Failed to create TCP interface %s: %v", ifaceConfig.Name, err)
				continue
			}
			
			// Convert callback type to match interface
			callback := func(data []byte, iface interface{}) {
				c.transport.HandlePacket(data, iface)
			}
			client.SetPacketCallback(common.PacketCallback(callback))
			iface = client

		case "udp":
			addr := fmt.Sprintf("%s:%d", ifaceConfig.Address, ifaceConfig.Port)
			udp, err := interfaces.NewUDPInterface(
				ifaceConfig.Name,
				addr,
				"", // No target address for client initially
			)
			if err != nil {
				log.Printf("Failed to create UDP interface %s: %v", ifaceConfig.Name, err)
				continue
			}
			
			// Convert callback type to match interface
			callback := func(data []byte, iface interface{}) {
				c.transport.HandlePacket(data, iface)
			}
			udp.SetPacketCallback(common.PacketCallback(callback))
			iface = udp

		default:
			log.Printf("Unknown interface type: %s", ifaceConfig.Type)
			continue
		}

		c.interfaces = append(c.interfaces, iface)
	}

	return nil
}

func (c *Client) Stop() {
	for _, iface := range c.interfaces {
		iface.Detach()
	}
	c.transport.Close()
}

func main() {
	flag.Parse()

	var cfg *common.ReticulumConfig
	var err error

	if *configPath == "" {
		cfg, err = config.InitConfig()
	} else {
		cfg, err = config.LoadConfig(*configPath)
	}
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *generateIdentity {
		id, err := identity.New()
		if err != nil {
			log.Fatalf("Failed to generate identity: %v", err)
		}
		fmt.Printf("Identity hash: %s\n", id.Hex())
		return
	}

	client, err := NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Stop()

	if err := client.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func interactiveLoop(link *transport.Link) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "quit" || input == "exit" {
			return
		}

		if err := link.Send([]byte(input)); err != nil {
			fmt.Printf("Failed to send: %v\n", err)
		}
	}
}