package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
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
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

type AnnounceClient struct {
	config     *common.ReticulumConfig
	identity   *identity.Identity
	interval   time.Duration
	announceID []byte
	data       string
	transport  *transport.Transport
	channel    *channel.Channel
	buffer     *buffer.RawChannelWriter
	done       chan struct{}
}

func NewAnnounceClient(cfg *common.ReticulumConfig, interval time.Duration, data string) (*AnnounceClient, error) {
	id, err := identity.New()
	if err != nil {
		return nil, err
	}

	t, err := transport.NewTransport(cfg)
	if err != nil {
		return nil, err
	}

	// Create transport wrapper that implements LinkInterface
	tw := &transportWrapper{t}

	// Create channel using transport wrapper
	ch := channel.NewChannel(tw)

	// Create buffer writer for streaming data
	writer := buffer.NewRawChannelWriter(1, ch)

	announceID := identity.GetRandomHash()

	client := &AnnounceClient{
		config:     cfg,
		identity:   id,
		interval:   interval,
		announceID: announceID,
		data:       data,
		transport:  t,
		channel:    ch,
		buffer:     writer,
		done:       make(chan struct{}),
	}

	// Register announce handler
	handler := &AnnounceHandler{
		aspectFilter: []string{"*"},
	}
	t.RegisterAnnounceHandler(handler)

	return client, nil
}

func (c *AnnounceClient) handlePacket(data []byte) error {
	if len(data) < 2 {
		return errors.New("packet too short")
	}

	header := data[0]
	packetType := header & 0x03 // Extract packet type from header

	switch packetType {
	case announce.PACKET_TYPE_ANNOUNCE:
		log.Printf("Processing announce packet")
		return c.processAnnounce(data[1:])
	}

	return nil
}

func (c *AnnounceClient) processAnnounce(data []byte) error {
	if len(data) < 16 {
		return errors.New("invalid announce packet length")
	}

	destHash := data[:16]
	announceType := data[16]

	if announceType == announce.ANNOUNCE_IDENTITY {
		pubKey := data[17:81] // Ed25519 public key is 32 bytes
		appDataLen := binary.BigEndian.Uint16(data[81:83])
		appData := data[83 : 83+appDataLen]

		log.Printf("Received announce from %x", destHash)
		log.Printf("Public key: %x", pubKey)
		log.Printf("App data: %s", string(appData))
	}

	return nil
}

func (c *AnnounceClient) Start() error {
	if err := c.transport.Start(); err != nil {
		return err
	}

	log.Printf("Starting announce client with interval: %v", c.interval)
	log.Printf("Announce data: %s", c.data)
	log.Printf("Announce ID: %x", c.announceID)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Initial announce
	log.Printf("Sending initial announce...")
	if err := c.announce(); err != nil {
		return err
	}
	log.Printf("Initial announce sent successfully")

	for {
		select {
		case <-ticker.C:
			log.Printf("Sending periodic announce...")
			if err := c.announce(); err != nil {
				log.Printf("Failed to send announce: %v", err)
			} else {
				log.Printf("Announce sent successfully")
			}
		case <-c.done:
			return nil
		}
	}
}

func (c *AnnounceClient) announce() error {
	// Create announce packet
	announceData := []byte(c.data)

	packet := announce.NewAnnouncePacket(
		c.identity.GetPublicKey(),
		announceData,
		c.announceID,
	)

	// Write through buffer system
	_, err := c.buffer.Write(packet.Data)
	if err != nil {
		return fmt.Errorf("failed to write announce: %v", err)
	}

	return nil
}

func (c *AnnounceClient) Stop() {
	close(c.done)
	c.buffer.Close()
	if err := c.transport.Close(); err != nil {
		log.Printf("Error closing transport: %v", err)
	}
}

// Add AnnounceHandler type
type AnnounceHandler struct {
	aspectFilter []string
}

func (h *AnnounceHandler) ReceivedAnnounce(destHash []byte, announcedIdentity interface{}, appData []byte) error {
	// Type assert the identity if needed
	if id, ok := announcedIdentity.(*identity.Identity); ok {
		log.Printf("Received announce from %x (Identity: %x)", destHash, id.GetPublicKey())
	} else {
		log.Printf("Received announce from %x", destHash)
	}
	log.Printf("App data: %s", string(appData))
	return nil
}

func (h *AnnounceHandler) ReceivePathResponses() bool {
	return true
}

// Add AspectFilter method to satisfy the interface
func (h *AnnounceHandler) AspectFilter() []string {
	return h.aspectFilter
}

// Add transportWrapper implementation
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
			packet.PacketTypeData,
			0,
		},
		Data:      data,
		Addresses: make([]byte, packet.AddressSize),
		Context:   0,
		Timestamp: time.Now(),
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

func (tw *transportWrapper) SetPacketTimeout(p interface{}, callback func(interface{}), timeout time.Duration) {
	time.AfterFunc(timeout, func() {
		callback(p)
	})
}

func (tw *transportWrapper) SetPacketDelivered(p interface{}, callback func(interface{})) {
	callback(p)
}

func main() {
	interval := flag.Int("interval", 600, "Announce interval in seconds")
	announceData := flag.String("data", "Hello Reticulum", "Data to announce")
	configPath := flag.String("config", "", "Path to config file")
	flag.Parse()

	log.Printf("Initializing announce client...")
	log.Printf("Config path: %s", *configPath)
	log.Printf("Interval: %d seconds", *interval)
	log.Printf("Data: %s", *announceData)

	cfg, err := config.InitConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	if *configPath != "" {
		cfg.ConfigPath = *configPath
		log.Printf("Using custom config path: %s", *configPath)
	}

	client, err := NewAnnounceClient(cfg, time.Duration(*interval)*time.Second, *announceData)
	if err != nil {
		log.Fatalf("Failed to create announce client: %v", err)
	}

	log.Printf("Client created successfully")
	log.Printf("Press Ctrl+C to stop...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("\nShutting down...")
		client.Stop()
		os.Exit(0)
	}()

	if err := client.Start(); err != nil {
		log.Fatalf("Error running announce client: %v", err)
	}
}
