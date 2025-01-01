package announce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
	mutex           *sync.RWMutex
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
	packet          []byte
}

func New(dest *identity.Identity, appData []byte, pathResponse bool) (*Announce, error) {
	if dest == nil {
		return nil, errors.New("destination identity required")
	}

	a := &Announce{
		mutex:        &sync.RWMutex{},
		identity:     dest,
		appData:      appData,
		hops:         0,
		timestamp:    time.Now().Unix(),
		pathResponse: pathResponse,
		retries:      0,
		handlers:     make([]AnnounceHandler, 0),
	}

	// Generate truncated hash from public key
	pubKey := dest.GetPublicKey()
	hash := sha256.Sum256(pubKey)
	a.destinationHash = hash[:identity.TRUNCATED_HASHLENGTH/8]

	// Get current ratchet ID if enabled
	currentRatchet := dest.GetCurrentRatchetKey()
	if currentRatchet != nil {
		a.ratchetID = dest.GetRatchetID(currentRatchet)
	}

	// Sign announce data
	signData := append(a.destinationHash, a.appData...)
	if a.ratchetID != nil {
		signData = append(signData, a.ratchetID...)
	}
	a.signature = dest.Sign(signData)

	return a, nil
}

func (a *Announce) Propagate(interfaces []common.NetworkInterface) error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	// Use cached packet if available, otherwise create new one
	var packet []byte
	if a.packet != nil {
		packet = a.packet
	} else {
		packet = a.CreatePacket()
		a.packet = packet
	}

	for _, iface := range interfaces {
		if !iface.IsEnabled() || !iface.GetBandwidthAvailable() {
			continue
		}

		if err := iface.Send(packet, ""); err != nil {
			return fmt.Errorf("failed to propagate on interface %s: %w", iface.GetName(), err)
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

	// Minimum packet size validation (2 header + 16 hash + 32 pubkey + 1 hops + 2 appdata len + 64 sig)
	if len(data) < 117 {
		return errors.New("invalid announce data length")
	}

	// Parse header
	header := data[:2]
	hopCount := header[1]
	if hopCount > MAX_HOPS {
		return errors.New("announce exceeded maximum hop count")
	}

	// Extract fields
	destHash := data[2:18]
	publicKey := data[18:50]
	hopsByte := data[50]

	// Validate hop count matches header
	if hopsByte != hopCount {
		return errors.New("inconsistent hop count in packet")
	}

	// Extract app data length and content
	appDataLen := binary.BigEndian.Uint16(data[51:53])
	appDataEnd := 53 + int(appDataLen)

	if appDataEnd > len(data) {
		return errors.New("invalid app data length")
	}

	appData := data[53:appDataEnd]

	// Handle ratchet ID if present
	var ratchetID []byte
	signatureStart := appDataEnd

	remainingBytes := len(data) - appDataEnd
	if remainingBytes > ed25519.SignatureSize {
		ratchetID = data[appDataEnd : len(data)-ed25519.SignatureSize]
		signatureStart = len(data) - ed25519.SignatureSize
	}

	if signatureStart+ed25519.SignatureSize > len(data) {
		return errors.New("invalid signature position")
	}

	signature := data[signatureStart:]

	// Create announced identity
	announcedIdentity := identity.FromPublicKey(publicKey)
	if announcedIdentity == nil {
		return errors.New("invalid identity public key")
	}

	// Verify signature
	signData := append(destHash, appData...)
	if ratchetID != nil {
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

	// Create header according to spec
	header := CreateHeader(
		IFAC_NONE,            // No interface auth
		HEADER_TYPE_1,        // One address field
		0x00,                 // Context flag unset
		PROP_TYPE_BROADCAST,  // Broadcast propagation
		DEST_TYPE_SINGLE,     // Single destination
		PACKET_TYPE_ANNOUNCE, // Announce packet type
		a.hops,               // Current hop count
	)
	packet = append(packet, header...)

	// Add destination hash (16 bytes)
	packet = append(packet, a.destinationHash...)

	// Add public key
	packet = append(packet, a.identity.GetPublicKey()...)

	// Add hop count byte
	packet = append(packet, byte(a.hops))

	// Add app data with length prefix
	appDataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(appDataLen, uint16(len(a.appData)))
	packet = append(packet, appDataLen...)
	packet = append(packet, a.appData...)

	// Add ratchet ID if present
	if a.ratchetID != nil {
		packet = append(packet, a.ratchetID...)
	}

	// Add signature
	signData := append(a.destinationHash, a.appData...)
	if a.ratchetID != nil {
		signData = append(signData, a.ratchetID...)
	}
	signature := a.identity.Sign(signData)
	packet = append(packet, signature...)

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

// NewAnnounce creates a new announce packet for a destination
func NewAnnounce(identity *identity.Identity, appData []byte, ratchetID []byte, pathResponse bool) (*Announce, error) {
	if identity == nil {
		return nil, errors.New("identity cannot be nil")
	}

	a := &Announce{
		identity:        identity,
		appData:         appData,
		ratchetID:       ratchetID,
		pathResponse:    pathResponse,
		destinationHash: identity.Hash(),
		hops:            0,
		mutex:           &sync.RWMutex{},
		handlers:        make([]AnnounceHandler, 0),
	}

	// Create announce packet
	packet := make([]byte, 0)

	// Add header (2 bytes)
	packet = append(packet, PACKET_TYPE_ANNOUNCE)
	packet = append(packet, byte(a.hops))

	// Add destination hash (16 bytes)
	packet = append(packet, a.destinationHash...)

	// Add public key (32 bytes)
	packet = append(packet, identity.GetPublicKey()...)

	// Add hop count (1 byte)
	packet = append(packet, byte(a.hops))

	// Add app data with length prefix (2 bytes + data)
	appDataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(appDataLen, uint16(len(appData)))
	packet = append(packet, appDataLen...)
	packet = append(packet, appData...)

	// Add ratchet ID if present
	if ratchetID != nil {
		packet = append(packet, ratchetID...)
	}

	// Add signature
	signData := append(a.destinationHash, appData...)
	if ratchetID != nil {
		signData = append(signData, ratchetID...)
	}
	signature := identity.Sign(signData)
	packet = append(packet, signature...)

	a.packet = packet

	return a, nil
}
