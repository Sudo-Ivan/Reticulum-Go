package announce

import (
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
	// Packet Types
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

	// Destination Types
	DEST_TYPE_SINGLE = 0x00
	DEST_TYPE_GROUP  = 0x01
	DEST_TYPE_PLAIN  = 0x02
	DEST_TYPE_LINK   = 0x03

	// IFAC Flag
	IFAC_NONE = 0x00
	IFAC_AUTH = 0x80 // Most significant bit

	MAX_HOPS         = 128
	PROPAGATION_RATE = 0.02 // 2% of interface bandwidth
	RETRY_INTERVAL   = 300  // 5 minutes
	MAX_RETRIES      = 3
)

type AnnounceHandler interface {
	AspectFilter() []string
	ReceivedAnnounce(destinationHash []byte, announcedIdentity *identity.Identity, appData []byte) error
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
}

func New(dest *identity.Identity, appData []byte, pathResponse bool) (*Announce, error) {
	a := &Announce{
		identity:     dest,
		appData:      appData,
		hops:         0,
		timestamp:    time.Now().Unix(),
		pathResponse: pathResponse,
		retries:      0,
		handlers:     make([]AnnounceHandler, 0),
	}

	// Generate destination hash
	hash := sha256.New()
	hash.Write(dest.GetPublicKey())
	a.destinationHash = hash.Sum(nil)[:16] // Truncated hash

	// Sign the announce
	signData := append(a.destinationHash, a.appData...)
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
		log.Printf("  Interface Type: %s", iface.GetType())
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

	// Enhanced validation logging
	log.Printf("Received announce data (%d bytes):", len(data))
	log.Printf("  Raw Data: %x", data)

	// Validate announce data
	if len(data) < 16+32+1 { // Min size: hash + pubkey + hops
		log.Printf("  Error: Invalid announce data length (got %d, need at least %d)", 
			len(data), 16+32+1)
		return errors.New("invalid announce data")
	}

	// Extract and log fields
	destHash := data[:16]
	publicKey := data[16:48]
	hopCount := data[48]

	log.Printf("  Destination Hash: %x", destHash)
	log.Printf("  Public Key: %x", publicKey)
	log.Printf("  Hop Count: %d", hopCount)

	if hopCount > MAX_HOPS {
		log.Printf("  Error: Exceeded maximum hop count (%d > %d)", hopCount, MAX_HOPS)
		return errors.New("announce exceeded maximum hop count")
	}

	// Extract app data and signature
	appData := data[49 : len(data)-64]
	signature := data[len(data)-64:]

	log.Printf("  App Data (%d bytes): %s", len(appData), string(appData))
	log.Printf("  Signature: %x", signature)

	// Create announced identity from public key
	announcedIdentity := identity.FromPublicKey(publicKey)
	if announcedIdentity == nil {
		log.Printf("  Error: Invalid identity public key")
		return errors.New("invalid identity public key")
	}

	// Verify signature
	signData := append(destHash, appData...)
	if !announcedIdentity.Verify(signData, signature) {
		log.Printf("  Error: Invalid announce signature")
		return errors.New("invalid announce signature")
	}

	log.Printf("  Signature verification successful")

	// Process announce with registered handlers
	for _, handler := range a.handlers {
		if handler.ReceivePathResponses() || !a.pathResponse {
			if err := handler.ReceivedAnnounce(destHash, announcedIdentity, appData); err != nil {
				log.Printf("  Handler error: %v", err)
				return err
			}
		}
	}

	log.Printf("  Successfully processed announce")
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
