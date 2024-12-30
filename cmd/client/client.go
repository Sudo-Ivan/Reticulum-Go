package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/link"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

var (
	configPath       = flag.String("config", "", "Path to config file")
	targetHash       = flag.String("target", "", "Target destination hash")
	generateIdentity = flag.Bool("generate-identity", false, "Generate a new identity and print its hash")
)

type Client struct {
	config     *common.ReticulumConfig
	transport  *transport.Transport
	interfaces []common.NetworkInterface
	identity   *identity.Identity
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

	id, err := identity.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %v", err)
	}

	return &Client{
		config:     cfg,
		transport:  t,
		interfaces: make([]common.NetworkInterface, 0),
		identity:   id,
	}, nil
}

func (c *Client) Start() error {
	// Initialize interfaces
	for _, ifaceConfig := range c.config.Interfaces {
		var iface common.NetworkInterface

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
				return fmt.Errorf("failed to create TCP interface %s: %v", ifaceConfig.Name, err)
			}
			iface = client

		case "UDPInterface":
			addr := fmt.Sprintf("%s:%d", ifaceConfig.Address, ifaceConfig.Port)
			udp, err := interfaces.NewUDPInterface(
				ifaceConfig.Name,
				addr,
				"", // No target address for client initially
			)
			if err != nil {
				return fmt.Errorf("failed to create UDP interface %s: %v", ifaceConfig.Name, err)
			}
			iface = udp

		default:
			return fmt.Errorf("unsupported interface type: %s", ifaceConfig.Type)
		}

		c.interfaces = append(c.interfaces, iface)
		log.Printf("Created interface %s", iface.GetName())
	}

	// Start periodic announces
	go func() {
		for {
			c.sendAnnounce()
			time.Sleep(30 * time.Second)
		}
	}()

	log.Printf("Client started with %d interfaces", len(c.interfaces))
	return nil
}

func (c *Client) handlePacket(data []byte, p *packet.Packet) {
	if len(data) < 1 {
		return
	}

	packetType := data[0]
	switch packetType {
	case 0x04: // Announce packet
		c.handleAnnounce(data[1:])
	default:
		c.transport.HandlePacket(data, p)
	}
}

func (c *Client) handleAnnounce(data []byte) {
	if len(data) < 42 { // 32 bytes hash + 8 bytes timestamp + 1 byte hops + 1 byte flags
		log.Printf("Received malformed announce packet (too short)")
		return
	}

	destHash := data[:32]
	timestamp := binary.BigEndian.Uint64(data[32:40])
	hops := data[40]
	flags := data[41]

	log.Printf("Received announce from %x", destHash)
	log.Printf("  Timestamp: %d", timestamp)
	log.Printf("  Hops: %d", hops)
	log.Printf("  Flags: %x", flags)

	if len(data) > 42 {
		// Extract app data if present
		dataLen := binary.BigEndian.Uint16(data[42:44])
		if len(data) >= 44+int(dataLen) {
			appData := data[44 : 44+dataLen]
			log.Printf("  App Data: %s", string(appData))
		}
	}
}

func (c *Client) sendAnnounce() {
	announceData := make([]byte, 0)

	// Packet type (1 byte)
	announceData = append(announceData, 0x04)

	// Destination hash (16 bytes)
	destHash := identity.TruncatedHash(c.identity.GetPublicKey())
	announceData = append(announceData, destHash...)

	// Timestamp (8 bytes)
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))
	announceData = append(announceData, timeBytes...)

	// Hops (1 byte)
	announceData = append(announceData, 0x00)

	// Flags (1 byte)
	announceData = append(announceData, 0x00)

	// Public key
	announceData = append(announceData, c.identity.GetPublicKey()...)

	// App data with length prefix
	appData := []byte("RNS.Go.Client")
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(appData)))
	announceData = append(announceData, lenBytes...)
	announceData = append(announceData, appData...)

	// Sign the announce data
	signData := append(destHash, c.identity.GetPublicKey()...)
	signData = append(signData, appData...)
	signature := c.identity.Sign(signData)
	announceData = append(announceData, signature...)

	log.Printf("Sending announce for identity: %s", c.identity.Hex())
	log.Printf("Announce packet length: %d bytes", len(announceData))
	log.Printf("Announce packet hex: %x", announceData)

	for _, iface := range c.interfaces {
		if err := iface.Send(announceData, ""); err != nil {
			log.Printf("Failed to send announce on interface %s: %v", iface.GetName(), err)
		} else {
			log.Printf("Sent announce on interface %s", iface.GetName())
		}
	}
}

func (c *Client) Stop() {
	for _, iface := range c.interfaces {
		iface.Detach()
	}
	c.transport.Close()
}

func (c *Client) Connect(destHash []byte) error {
	// Recall server identity
	serverIdentity, err := identity.Recall(destHash)
	if err != nil {
		return err
	}

	// Create destination
	dest, err := destination.New(
		serverIdentity,
		destination.OUT,
		destination.SINGLE,
		"example_utilities",
		"identifyexample",
	)
	if err != nil {
		return err
	}

	// Create link with all required parameters
	link := link.NewLink(
		dest,
		c.transport, // Add the transport instance
		c.handleLinkEstablished,
		c.handleLinkClosed,
	)

	// Set callbacks
	link.SetPacketCallback(c.handlePacket)

	return nil
}

func (c *Client) handleLinkEstablished(l *link.Link) {
	log.Printf("Link established with server, identifying...")

	// Identify to server
	if err := l.Identify(c.identity); err != nil {
		log.Printf("Failed to identify: %v", err)
		l.Teardown()
		return
	}
}

func (c *Client) handleLinkClosed(l *link.Link) {
	log.Printf("Link closed")
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
