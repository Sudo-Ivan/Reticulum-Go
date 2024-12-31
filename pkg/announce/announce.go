package announce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
)

const (
	PACKET_TYPE_DATA     = 0x00
	PACKET_TYPE_ANNOUNCE = 0x01
	PACKET_TYPE_LINK     = 0x02
	PACKET_TYPE_PROOF    = 0x03

	// Announce Types
	ANNOUNCE_NONE     = 0x00
	ANNOUNCE_PATH     = 0x01
	ANNOUNCE_IDENTITY = 0x02

	// Header Types
	HEADER_TYPE_1 = 0x00 // One address field
	HEADER_TYPE_2 = 0x01 // Two address fields

	// Propagation Types
	PROP_TYPE_BROADCAST = 0x00
	PROP_TYPE_TRANSPORT = 0x01

	DEST_TYPE_SINGLE = 0x00
	DEST_TYPE_GROUP  = 0x01
	DEST_TYPE_PLAIN  = 0x02
	DEST_TYPE_LINK   = 0x03

	// IFAC Flag
	IFAC_NONE = 0x00
	IFAC_AUTH = 0x80

	MAX_HOPS         = 128
	PROPAGATION_RATE = 0.02 // 2% of interface bandwidth
	RETRY_INTERVAL   = 300  // 5 minutes
	MAX_RETRIES      = 3
)

type AnnounceHandler interface {
	AspectFilter() []string
	ReceivedAnnounce(destinationHash []byte, announcedIdentity interface{}, appData []byte) error
	ReceivePathResponses() bool
}

type Announce struct {
	mutex           sync.RWMutex
	destinationHash []byte
	identity        *identity.Identity
	appData         []byte
	hops            uint8
	timestamp       int64
	signature       []byte
	pathResponse    bool
	retries         int
	handlers        []AnnounceHandler
	ratchetID       []byte
}

func New(dest *identity.Identity, appData []byte, pathResponse bool) (*Announce, error) {
	if dest == nil {
		return nil, errors.New("destination identity required")
	}

	a := &Announce{
		identity:     dest,
		appData:      appData,
		hops:         0,
		timestamp:    time.Now().Unix(),
		pathResponse: pathResponse,
		retries:      0,
		handlers:     make([]AnnounceHandler, 0),
	}

	// Generate truncated hash
	hash := sha256.New()
	hash.Write(dest.GetPublicKey())
	a.destinationHash = hash.Sum(nil)[:identity.TRUNCATED_HASHLENGTH/8]

	// Sign announce data
	signData := append(a.destinationHash, a.appData...)
	if dest.GetRatchetID(nil) != nil {
		a.ratchetID = dest.GetRatchetID(nil)
		signData = append(signData, a.ratchetID...)
	}
	a.signature = dest.Sign(signData)

	return a, nil
}

func (a *Announce) Propagate(interfaces []common.NetworkInterface) error {
	packet := a.CreatePacket()

	// Enhanced logging
	log.Printf("Creating announce packet:")
	log.Printf("  Destination Hash: %x", a.destinationHash)
	log.Printf("  Identity Public Key: %x", a.identity.GetPublicKey())
	log.Printf("  App Data: %s", string(a.appData))
	log.Printf("  Signature: %x", a.signature)
	log.Printf("  Total Packet Size: %d bytes", len(packet))
	log.Printf("  Raw Packet: %x", packet)

	// Propagate to interfaces
	for _, iface := range interfaces {
		log.Printf("Propagating on interface %s:", iface.GetName())
		log.Printf("  Interface Type: %d", iface.GetType())
		log.Printf("  MTU: %d bytes", iface.GetMTU())

		if err := iface.Send(packet, ""); err != nil {
			log.Printf("  Failed to propagate: %v", err)
		} else {
			log.Printf("  Successfully propagated")
		}
	}

	return nil
}

func (a *Announce) RegisterHandler(handler AnnounceHandler) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.handlers = append(a.handlers, handler)
}

func (a *Announce) DeregisterHandler(handler AnnounceHandler) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for i, h := range a.handlers {
		if h == handler {
			a.handlers = append(a.handlers[:i], a.handlers[i+1:]...)
			break
		}
	}
}

func (a *Announce) HandleAnnounce(data []byte) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if len(data) < identity.TRUNCATED_HASHLENGTH/8+identity.KEYSIZE/8+1 {
		return errors.New("invalid announce data length")
	}

	destHash := data[:identity.TRUNCATED_HASHLENGTH/8]
	publicKey := data[identity.TRUNCATED_HASHLENGTH/8 : identity.TRUNCATED_HASHLENGTH/8+identity.KEYSIZE/8]
	hopCount := data[identity.TRUNCATED_HASHLENGTH/8+identity.KEYSIZE/8]

	if hopCount > MAX_HOPS {
		return errors.New("announce exceeded maximum hop count")
	}

	// Extract app data and signature
	dataStart := identity.TRUNCATED_HASHLENGTH/8 + identity.KEYSIZE/8 + 1
	appData := data[dataStart : len(data)-ed25519.SignatureSize]
	signature := data[len(data)-ed25519.SignatureSize:]

	// Create announced identity
	announcedIdentity := identity.FromPublicKey(publicKey)
	if announcedIdentity == nil {
		return errors.New("invalid identity public key")
	}

	// Verify signature including ratchet if present
	signData := append(destHash, appData...)
	if len(appData) > 32 { // Check for ratchet
		ratchetID := appData[len(appData)-32:]
		signData = append(signData, ratchetID...)
	}

	if !announcedIdentity.Verify(signData, signature) {
		return errors.New("invalid announce signature")
	}

	// Process with handlers
	for _, handler := range a.handlers {
		if handler.ReceivePathResponses() || !a.pathResponse {
			if err := handler.ReceivedAnnounce(destHash, announcedIdentity, appData); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *Announce) RequestPath(destHash []byte, onInterface common.NetworkInterface) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Create path request packet
	packet := make([]byte, 0)
	packet = append(packet, destHash...)
	packet = append(packet, byte(0)) // Initial hop count

	// Send path request
	if err := onInterface.Send(packet, ""); err != nil {
		return err
	}

	return nil
}

// CreateHeader creates a Reticulum packet header according to spec
func CreateHeader(ifacFlag byte, headerType byte, contextFlag byte, propType byte, destType byte, packetType byte, hops byte) []byte {
	header := make([]byte, 2)

	// First byte: [IFAC Flag], [Header Type], [Context Flag], [Propagation Type], [Destination Type] and [Packet Type]
	header[0] = ifacFlag | (headerType << 6) | (contextFlag << 5) |
		(propType << 4) | (destType << 2) | packetType

	// Second byte: Number of hops
	header[1] = hops

	return header
}

func (a *Announce) CreatePacket() []byte {
	packet := make([]byte, 0)

	// Create header for announce packet
	header := CreateHeader(
		IFAC_NONE,            // No interface authentication
		HEADER_TYPE_1,        // One address field
		0x00,                 // Context flag unset
		PROP_TYPE_BROADCAST,  // Broadcast propagation
		DEST_TYPE_SINGLE,     // Single destination
		PACKET_TYPE_ANNOUNCE, // Announce packet type
		byte(a.hops),         // Current hop count
	)
	packet = append(packet, header...)

	// Add destination hash (16 bytes)
	packet = append(packet, a.destinationHash...)

	// Add context byte
	packet = append(packet, ANNOUNCE_IDENTITY)

	// Add public key
	packet = append(packet, a.identity.GetPublicKey()...)

	// Add app data with length prefix
	if a.appData != nil {
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(a.appData)))
		packet = append(packet, lenBytes...)
		packet = append(packet, a.appData...)
	}

	// Add signature
	packet = append(packet, a.signature...)

	return packet
}

type AnnouncePacket struct {
	Data []byte
}

func NewAnnouncePacket(pubKey []byte, appData []byte, announceID []byte) *AnnouncePacket {
	packet := &AnnouncePacket{}
	
	// Build packet data
	packet.Data = make([]byte, 0, len(pubKey)+len(appData)+len(announceID)+4)
	
	// Add header
	packet.Data = append(packet.Data, PACKET_TYPE_ANNOUNCE)
	packet.Data = append(packet.Data, ANNOUNCE_IDENTITY)
	
	// Add public key
	packet.Data = append(packet.Data, pubKey...)
	
	// Add app data length and content
	appDataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(appDataLen, uint16(len(appData)))
	packet.Data = append(packet.Data, appDataLen...)
	packet.Data = append(packet.Data, appData...)
	
	// Add announce ID
	packet.Data = append(packet.Data, announceID...)
	
	return packet
}
