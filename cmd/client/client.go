package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
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
	log.Printf("Starting Reticulum client...")
	log.Printf("Configuration: %+v", c.config)

	// Initialize transport
	t, err := transport.NewTransport(c.config)
	if err != nil {
		return fmt.Errorf("failed to initialize transport: %v", err)
	}
	c.transport = t
	log.Printf("Transport initialized")

	log.Printf("Initializing network interfaces...")
	for name, ifaceConfig := range c.config.Interfaces {
		if !ifaceConfig.Enabled {
			log.Printf("Skipping disabled interface %s", name)
			continue
		}

		log.Printf("Configuring interface %s (%s)", name, ifaceConfig.Type)
		var iface common.NetworkInterface

		switch ifaceConfig.Type {
		case "TCPClientInterface":
			log.Printf("Connecting to %s:%d via TCP...", ifaceConfig.TargetHost, ifaceConfig.TargetPort)
			client, err := interfaces.NewTCPClient(
				name,
				ifaceConfig.TargetHost,
				ifaceConfig.TargetPort,
				ifaceConfig.KISSFraming,
				ifaceConfig.I2PTunneled,
				ifaceConfig.Enabled,
			)
			if err != nil {
				return fmt.Errorf("failed to create TCP interface %s: %v", name, err)
			}

			if err := client.Start(); err != nil {
				return fmt.Errorf("failed to start TCP interface %s: %v", name, err)
			}

			iface = client
			log.Printf("Successfully connected to %s:%d", ifaceConfig.TargetHost, ifaceConfig.TargetPort)

		case "UDPInterface":
			addr := fmt.Sprintf("%s:%d", ifaceConfig.Address, ifaceConfig.Port)
			target := fmt.Sprintf("%s:%d", ifaceConfig.TargetHost, ifaceConfig.TargetPort)
			log.Printf("Starting UDP interface on %s...", addr)
			udp, err := interfaces.NewUDPInterface(
				name,
				addr,
				target,
				ifaceConfig.Enabled,
			)
			if err != nil {
				return fmt.Errorf("failed to create UDP interface %s: %v", name, err)
			}

			if err := udp.Start(); err != nil {
				return fmt.Errorf("failed to start UDP interface %s: %v", name, err)
			}

			iface = udp
			log.Printf("UDP interface listening on %s", addr)
		}

		if iface != nil {
			// Set packet callback
			iface.SetPacketCallback(c.transport.HandlePacket)
			c.interfaces = append(c.interfaces, iface)
			log.Printf("Created and started interface %s (type=%v, enabled=%v)",
				name, iface.GetType(), iface.IsEnabled())
		}
	}

	// Register announce handler with explicit type
	var handler transport.AnnounceHandler = &ClientAnnounceHandler{client: c}
	c.transport.RegisterAnnounceHandler(handler)

	// Send initial announce
	log.Printf("Sending initial announce...")
	if err := c.sendAnnounce(); err != nil {
		log.Printf("Warning: Failed to send initial announce: %v", err)
	}

	return nil
}

func (c *Client) handlePacket(data []byte, p *packet.Packet) {
	if len(data) < 1 {
		return
	}

	header := data[0]
	packetType := header & 0x03 // Extract packet type from header

	switch packetType {
	case announce.PACKET_TYPE_ANNOUNCE:
		log.Printf("Received announce packet:")
		log.Printf("  Raw data: %x", data)

		// Create announce instance
		a, err := announce.New(c.identity, []byte("RNS.Go.Client"), false)
		if err != nil {
			log.Printf("Failed to create announce handler: %v", err)
			return
		}

		// Handle the announce
		if err := a.HandleAnnounce(data[1:]); err != nil {
			log.Printf("Failed to handle announce: %v", err)
		}

	default:
		c.transport.HandlePacket(data, p)
	}
}

func (c *Client) handleAnnounce(data []byte) {
	if len(data) < 42 {
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

	// Extract public key if present (after flags)
	if len(data) > 42 {
		pubKeyLen := 32 // Ed25519 public key length
		pubKey := data[42 : 42+pubKeyLen]
		log.Printf("  Public Key: %x", pubKey)

		// Extract app data if present
		var appData []byte
		if len(data) > 42+pubKeyLen+2 {
			dataLen := binary.BigEndian.Uint16(data[42+pubKeyLen : 42+pubKeyLen+2])
			if len(data) >= 42+pubKeyLen+2+int(dataLen) {
				appData = data[42+pubKeyLen+2 : 42+pubKeyLen+2+int(dataLen)]
				log.Printf("  App Data: %s", string(appData))
			}
		}

		// Store the identity for future use with all required parameters
		if !identity.ValidateAnnounce(data, destHash, pubKey, data[len(data)-64:], appData) {
			log.Printf("Failed to validate announce")
			return
		}
		log.Printf("Successfully validated and stored announce")
	}
}

func (c *Client) sendAnnounce() error {
	// Create announce packet
	identityHash := c.identity.Hash()
	announceData := make([]byte, 0)

	// Add header
	header := []byte{0x01, 0x00} // Announce packet type
	announceData = append(announceData, header...)

	// Add destination hash
	announceData = append(announceData, identityHash...)

	// Add context byte
	announceData = append(announceData, announce.ANNOUNCE_IDENTITY)

	// Add public key
	announceData = append(announceData, c.identity.GetPublicKey()...)

	// App data with length prefix
	appData := []byte("RNS.Go.Client")
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(appData)))
	announceData = append(announceData, lenBytes...)
	announceData = append(announceData, appData...)

	// Add signature
	signData := append(identityHash, c.identity.GetPublicKey()...)
	signData = append(signData, appData...)
	signature := c.identity.Sign(signData)
	announceData = append(announceData, signature...)

	log.Printf("Sending announce:")
	log.Printf("  Identity Hash: %x", identityHash)
	log.Printf("  Packet Length: %d bytes", len(announceData))
	log.Printf("  Full Packet: %x", announceData)

	sentCount := 0
	// Send on all interfaces
	for _, iface := range c.interfaces {
		log.Printf("Attempting to send on interface %s:", iface.GetName())
		log.Printf("  Type: %v", iface.GetType())
		log.Printf("  MTU: %d bytes", iface.GetMTU())
		log.Printf("  Status: enabled=%v", iface.IsEnabled())

		if !iface.IsEnabled() {
			log.Printf("  Skipping disabled interface")
			continue
		}

		if err := iface.Send(announceData, ""); err != nil {
			log.Printf("  Failed to send: %v", err)
		} else {
			log.Printf("  Successfully sent announce")
			sentCount++
		}
	}

	if sentCount == 0 {
		return fmt.Errorf("no interfaces available to send announce")
	}

	return nil
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

type ClientAnnounceHandler struct {
	client *Client
}

func (h *ClientAnnounceHandler) AspectFilter() []string {
	return []string{"RNS.Go.Client"}
}

func (h *ClientAnnounceHandler) ReceivedAnnounce(destinationHash []byte, announcedIdentity interface{}, appData []byte) error {
	log.Printf("=== Received Announce Details ===")
	log.Printf("Destination Hash: %x", destinationHash)
	log.Printf("App Data: %s", string(appData))

	// Type assert the identity
	if id, ok := announcedIdentity.(*identity.Identity); ok {
		log.Printf("Identity Public Key: %x", id.GetPublicKey())

		// Create packet hash for storage
		packetHash := identity.TruncatedHash(append(destinationHash, id.GetPublicKey()...))
		log.Printf("Generated Packet Hash: %x", packetHash)

		// Store the peer identity with all required parameters
		identity.Remember(packetHash, destinationHash, id.GetPublicKey(), appData)
		log.Printf("Identity stored successfully")
		log.Printf("===========================")
		return nil
	}

	log.Printf("Error: Invalid identity type")
	log.Printf("===========================")
	return fmt.Errorf("invalid identity type")
}

func (h *ClientAnnounceHandler) ReceivePathResponses() bool {
	return true
}

func main() {
	flag.Parse()

	log.Printf("Starting Reticulum Go client...")
	log.Printf("Config path: %s", *configPath)
	log.Printf("Target hash: %s", *targetHash)

	var cfg *common.ReticulumConfig
	var err error

	if *configPath == "" {
		log.Printf("No config path specified, using default configuration")
		cfg, err = config.InitConfig()
	} else {
		log.Printf("Loading configuration from: %s", *configPath)
		cfg, err = config.LoadConfig(*configPath)
	}
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Configuration loaded successfully")

	if *generateIdentity {
		log.Printf("Generating new identity...")
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

	log.Printf("Client running, press Ctrl+C to exit")

	// If target is specified, start interactive mode
	if *targetHash != "" {
		targetBytes, err := identity.HashFromString(*targetHash)
		if err != nil {
			log.Fatalf("Invalid target hash: %v", err)
		}
		link, err := client.transport.GetLink(targetBytes)
		if err != nil {
			log.Fatalf("Failed to get link: %v", err)
		}
		log.Printf("Starting interactive mode...")
		interactiveLoop(link)
		return
	}

	// Wait for interrupt if no target specified
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Printf("Received interrupt signal, shutting down...")
}

func interactiveLoop(link *transport.Link) {
	reader := bufio.NewReader(os.Stdin)
	connected := make(chan struct{})
	disconnected := make(chan struct{})

	// Set up connection status handlers
	link.OnConnected(func() {
		connected <- struct{}{}
	})

	link.OnDisconnected(func() {
		disconnected <- struct{}{}
	})

	// Wait for initial connection
	select {
	case <-connected:
		log.Println("Connected to target")
	case <-time.After(10 * time.Second):
		log.Fatal("Connection timeout")
		return
	}

	// Start input loop
	for {
		select {
		case <-disconnected:
			log.Println("Connection lost")
			return
		default:
			fmt.Print("> ")
			input, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Printf("Error reading input: %v", err)
				continue
			}

			input = strings.TrimSpace(input)
			if input == "quit" || input == "exit" {
				return
			}

			if err := link.Send([]byte(input)); err != nil {
				log.Printf("Failed to send: %v", err)
				return
			}
		}
	}
}
