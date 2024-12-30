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
	"time"
	"encoding/binary"

	"github.com/Sudo-Ivan/reticulum-go/internal/config"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	"github.com/Sudo-Ivan/reticulum-go/pkg/interfaces"
	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
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
				log.Printf("Failed to create TCP interface %s: %v", ifaceConfig.Name, err)
				continue
			}
			
			callback := common.PacketCallback(func(data []byte, iface interface{}) {
				c.handlePacket(data, iface)
			})
			client.SetPacketCallback(callback)
			iface = client

		case "UDPInterface":
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
			
			callback := common.PacketCallback(func(data []byte, iface interface{}) {
				c.handlePacket(data, iface)
			})
			udp.SetPacketCallback(callback)
			iface = udp

		case "AutoInterface":
			log.Printf("AutoInterface type not yet implemented")
			continue

		default:
			log.Printf("Unknown interface type: %s", ifaceConfig.Type)
			continue
		}

		if iface != nil {
			c.interfaces = append(c.interfaces, iface)
		}
	}

	// Start periodic announce after interfaces are set up
	go func() {
		// Initial delay to allow interfaces to connect
		time.Sleep(5 * time.Second)
		
		// Send first announce
		c.sendAnnounce()
		
		// Set up periodic announces
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				c.sendAnnounce()
			}
		}
	}()

	log.Printf("Client started with %d interfaces", len(c.interfaces))
	return nil
}

func (c *Client) handlePacket(data []byte, iface interface{}) {
	if len(data) < 1 {
		return
	}

	packetType := data[0]
	switch packetType {
	case 0x04: // Announce packet
		c.handleAnnounce(data[1:])
	default:
		c.transport.HandlePacket(data, iface)
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
			appData := data[44:44+dataLen]
			log.Printf("  App Data: %s", string(appData))
		}
	}
}

func (c *Client) sendAnnounce() {
	// Create announce packet following RNS protocol
	announceData := make([]byte, 0, 128)
	announceData = append(announceData, 0x04)        // Announce packet type
	announceData = append(announceData, c.identity.Hash()...) // Identity hash (32 bytes)
	
	// Add timestamp (8 bytes, big-endian)
	timestamp := time.Now().Unix()
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp))
	announceData = append(announceData, timeBytes...)
	
	// Add hops (1 byte)
	announceData = append(announceData, 0x00) // Initial hop count
	
	// Add flags (1 byte)
	announceData = append(announceData, byte(announce.ANNOUNCE_IDENTITY)) // Using identity announce type
	
	// Add app data with length prefix
	appData := []byte("RNS.Go.Client")
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(appData)))
	announceData = append(announceData, lenBytes...)
	announceData = append(announceData, appData...)

	// Sign the announce packet
	signature := c.identity.Sign(announceData)
	announceData = append(announceData, signature...)

	log.Printf("Sending announce packet, length: %d bytes", len(announceData))

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