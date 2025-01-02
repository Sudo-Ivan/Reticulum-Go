package announce

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
	mutex           *sync.RWMutex
	destinationHash []byte
	identity        *identity.Identity
	appData         []byte
	config          *common.ReticulumConfig
	hops            uint8
	timestamp       int64
	signature       []byte
	pathResponse    bool
	retries         int
	handlers        []AnnounceHandler
	ratchetID       []byte
	packet          []byte
	hash            []byte
}

func New(dest *identity.Identity, appData []byte, pathResponse bool, config *common.ReticulumConfig) (*Announce, error) {
	if dest == nil {
		return nil, errors.New("destination identity required")
	}

	a := &Announce{
		mutex:        &sync.RWMutex{},
		identity:     dest,
		appData:      appData,
		config:       config,
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

	log.Printf("[DEBUG-7] Propagating announce across %d interfaces", len(interfaces))

	var packet []byte
	if a.packet != nil {
		log.Printf("[DEBUG-7] Using cached packet (%d bytes)", len(a.packet))
		packet = a.packet
	} else {
		log.Printf("[DEBUG-7] Creating new packet")
		packet = a.CreatePacket()
		a.packet = packet
	}

	for _, iface := range interfaces {
		if !iface.IsEnabled() {
			log.Printf("[DEBUG-7] Skipping disabled interface: %s", iface.GetName())
			continue
		}
		if !iface.GetBandwidthAvailable() {
			log.Printf("[DEBUG-7] Skipping interface with insufficient bandwidth: %s", iface.GetName())
			continue
		}

		log.Printf("[DEBUG-7] Sending announce on interface %s", iface.GetName())
		if err := iface.Send(packet, ""); err != nil {
			log.Printf("[DEBUG-7] Failed to send on interface %s: %v", iface.GetName(), err)
			return fmt.Errorf("failed to propagate on interface %s: %w", iface.GetName(), err)
		}
		log.Printf("[DEBUG-7] Successfully sent announce on interface %s", iface.GetName())
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

	log.Printf("[DEBUG-7] Handling announce packet of %d bytes", len(data))

	// Minimum packet size validation (2 header + 16 hash + 32 pubkey + 1 hops + 2 appdata len + 64 sig)
	if len(data) < 117 {
		log.Printf("[DEBUG-7] Invalid announce data length: %d bytes", len(data))
		return errors.New("invalid announce data length")
	}

	// Parse header
	header := data[:2]
	hopCount := header[1]
	log.Printf("[DEBUG-7] Announce header: type=%x, hops=%d", header[0], hopCount)

	if hopCount > MAX_HOPS {
		log.Printf("[DEBUG-7] Announce exceeded max hops: %d", hopCount)
		return errors.New("announce exceeded maximum hop count")
	}

	// Extract fields with detailed logging
	destHash := data[2:18]
	publicKey := data[18:50]
	hopsByte := data[50]

	log.Printf("[DEBUG-7] Announce fields: destHash=%x, pubKeyLen=%d, hops=%d",
		destHash, len(publicKey), hopsByte)

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
	log.Printf("[DEBUG-7] Creating announce packet")

	headerByte := byte(
		(IFAC_NONE) |
			(HEADER_TYPE_1 << 6) |
			(0 << 5) |
			(PROP_TYPE_BROADCAST << 4) |
			(DEST_TYPE_SINGLE << 2) |
			PACKET_TYPE_ANNOUNCE,
	)

	log.Printf("[DEBUG-7] Created header byte: %02x, hops: %d", headerByte, a.hops)
	packet := []byte{headerByte, a.hops}

	// Add destination hash (16 bytes)
	log.Printf("[DEBUG-7] Adding destination hash (16 bytes): %x", a.destinationHash)
	packet = append(packet, a.destinationHash...)

	// Get full public key and split into encryption and signing keys
	pubKey := a.identity.GetPublicKey()
	encKey := pubKey[:32]  // x25519 public key for encryption
	signKey := pubKey[32:] // Ed25519 public key for signing

	// Add encryption key (32 bytes)
	log.Printf("[DEBUG-7] Adding encryption key (32 bytes): %x", encKey)
	packet = append(packet, encKey...)

	// Add signing key (32 bytes)
	log.Printf("[DEBUG-7] Adding signing key (32 bytes): %x", signKey)
	packet = append(packet, signKey...)

	// Add name hash (10 bytes) - SHA256 hash of full name truncated to 10 bytes
	nameHash := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", a.config.AppName, a.config.AppAspect)))
	log.Printf("[DEBUG-7] Adding name hash (10 bytes): %x", nameHash[:10])
	packet = append(packet, nameHash[:10]...)

	// Add random hash (5 random + 5 timestamp bytes = 10 bytes)
	randomBytes := make([]byte, 5)
	rand.Read(randomBytes)
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))
	log.Printf("[DEBUG-7] Adding random hash (10 bytes): %x%x", randomBytes, timeBytes[:5])
	packet = append(packet, randomBytes...)
	packet = append(packet, timeBytes[:5]...)

	// Add ratchet if present (32 bytes)
	if a.ratchetID != nil {
		log.Printf("[DEBUG-7] Adding ratchet ID (32 bytes): %x", a.ratchetID)
		packet = append(packet, a.ratchetID...)
	}

	// Create msgpack array for app data
	appData := []byte{
		0x92, // msgpack array of 2 elements
		0xc4, // bin 8 format for byte array
	}

	// Add name bytes
	nameBytes := []byte(fmt.Sprintf("%s.%s", a.config.AppName, a.config.AppAspect))
	appData = append(appData, byte(len(nameBytes))) // length prefix
	appData = append(appData, nameBytes...)         // name bytes
	appData = append(appData, 0x00)                 // ticket value = 0

	// Add app data to packet
	packet = append(packet, appData...)

	// Create signature
	signData := append(a.destinationHash, appData...)
	if a.ratchetID != nil {
		signData = append(signData, a.ratchetID...)
	}
	signature := a.identity.Sign(signData)
	log.Printf("[DEBUG-7] Adding signature (64 bytes): %x", signature)
	packet = append(packet, signature...)

	log.Printf("[DEBUG-7] Final packet size: %d bytes", len(packet))
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
func NewAnnounce(identity *identity.Identity, appData []byte, ratchetID []byte, pathResponse bool, config *common.ReticulumConfig) (*Announce, error) {
	log.Printf("[DEBUG-7] Creating new announce: appDataLen=%d, hasRatchet=%v, pathResponse=%v",
		len(appData), ratchetID != nil, pathResponse)

	if identity == nil {
		log.Printf("[DEBUG-7] Error: nil identity provided")
		return nil, errors.New("identity cannot be nil")
	}

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	destHash := identity.Hash()
	log.Printf("[DEBUG-7] Generated destination hash: %x", destHash)

	a := &Announce{
		identity:        identity,
		appData:         appData,
		ratchetID:       ratchetID,
		pathResponse:    pathResponse,
		destinationHash: destHash,
		hops:            0,
		mutex:           &sync.RWMutex{},
		handlers:        make([]AnnounceHandler, 0),
		config:          config,
	}

	log.Printf("[DEBUG-7] Created announce object: destHash=%x, hops=%d",
		a.destinationHash, a.hops)

	// Create initial packet
	packet := a.CreatePacket()
	a.packet = packet

	// Generate hash
	hash := a.Hash()
	log.Printf("[DEBUG-7] Generated announce hash: %x", hash)

	return a, nil
}

func (a *Announce) Hash() []byte {
	if a.hash == nil {
		// Generate hash from announce data
		h := sha256.New()
		h.Write(a.destinationHash)
		h.Write(a.identity.GetPublicKey())
		h.Write([]byte{a.hops})
		h.Write(a.appData)
		if a.ratchetID != nil {
			h.Write(a.ratchetID)
		}
		a.hash = h.Sum(nil)
	}
	return a.hash
}

func (a *Announce) GetPacket() []byte {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.packet == nil {
		// Generate hash from announce data
		h := sha256.New()
		h.Write(a.destinationHash)
		h.Write(a.identity.GetPublicKey())
		h.Write([]byte{a.hops})
		h.Write(a.appData)
		if a.ratchetID != nil {
			h.Write(a.ratchetID)
		}

		// Construct packet
		packet := make([]byte, 0)
		packet = append(packet, PACKET_TYPE_ANNOUNCE)
		packet = append(packet, a.destinationHash...)
		packet = append(packet, a.identity.GetPublicKey()...)
		packet = append(packet, a.hops)
		packet = append(packet, a.appData...)
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

		a.packet = packet
	}

	return a.packet
}
