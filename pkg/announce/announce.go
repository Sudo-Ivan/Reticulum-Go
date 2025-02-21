package announce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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

	slog.Debug("Propagating announce", "#interfaces", len(interfaces))

	if a.packet != nil {
		slog.Debug("Using cached packet", "size", len(a.packet))
	} else {
		slog.Debug("Creating new packet")
		a.packet = a.CreatePacket()
	}
	var packet = a.packet

	for _, iface := range interfaces {
		if !iface.IsEnabled() {
			slog.Debug("Skipping disabled interface", "interface", iface.GetName())
			continue
		}
		if !iface.GetBandwidthAvailable() {
			slog.Debug("Skipping interface with insufficient bandwidth:", "interface", iface.GetName())
			continue
		}

		slog.Debug("Sending announce on interface", "interface", iface.GetName())
		if err := iface.Send(packet, ""); err != nil {
			slog.Warn("Failed to send on interface", "interface", iface.GetName(), "err", err)
			return fmt.Errorf("failed to propagate on interface %s: %w", iface.GetName(), err)
		}
		slog.Debug("Successfully sent announce", "interface", iface.GetName())
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

	slog.Debug("Handling announce packet", "length", len(data))

	// Minimum packet size validation (header(2) + desthash(16) + enckey(32) + signkey(32) + namehash(10) +
	// randomhash(10) + signature(64) + min app data(3))
	if len(data) < 169 {
		slog.Debug("Invalid announce data length", "length", len(data))
		return errors.New("invalid announce data length")
	}

	// Parse fields
	header := data[:2]
	hopCount := header[1]
	destHash := data[2:18]
	encKey := data[18:50]
	signKey := data[50:82]
	nameHash := data[82:92]
	randomHash := data[92:102]
	signature := data[102:166]
	appData := data[166:]

	slog.Debug("Announce fields", "destHash", hex.EncodeToString(destHash),
		"encKey", hex.EncodeToString(encKey),
		"signKey", hex.EncodeToString(signKey),
		"nameHash", hex.EncodeToString(nameHash),
		"randomHash", hex.EncodeToString(randomHash))

	// Validate hop count
	if hopCount > MAX_HOPS {
		slog.Debug("Announce exceeded max hops: %d", hopCount)
		return errors.New("announce exceeded maximum hop count")
	}

	// Create announced identity from public keys
	pubKey := append(encKey, signKey...)
	announcedIdentity := identity.FromPublicKey(pubKey)
	if announcedIdentity == nil {
		return errors.New("invalid identity public key")
	}

	// Verify signature
	signData := append(destHash, appData...)
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
	// Create header
	header := CreateHeader(
		IFAC_NONE,
		HEADER_TYPE_1,
		0, // No context flag
		PROP_TYPE_BROADCAST,
		DEST_TYPE_SINGLE,
		PACKET_TYPE_ANNOUNCE,
		a.hops,
	)

	packet := header

	// Add destination hash (16 bytes)
	packet = append(packet, a.destinationHash...)

	// Add public key parts (32 bytes each)
	pubKey := a.identity.GetPublicKey()
	packet = append(packet, pubKey[:32]...) // Encryption key
	packet = append(packet, pubKey[32:]...) // Signing key

	// Add name hash (10 bytes)
	nameHash := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", a.config.AppName, a.config.AppAspect)))
	packet = append(packet, nameHash[:10]...)

	// Add random hash (10 bytes)
	randomBytes := make([]byte, 10)
	rand.Read(randomBytes)
	packet = append(packet, randomBytes...)

	// Create validation data for signature
	validationData := make([]byte, 0)
	validationData = append(validationData, a.destinationHash...)
	validationData = append(validationData, pubKey[:32]...) // Encryption key
	validationData = append(validationData, pubKey[32:]...) // Signing key
	validationData = append(validationData, nameHash[:10]...)
	validationData = append(validationData, randomBytes...)
	validationData = append(validationData, a.appData...)

	// Add signature (64 bytes)
	signature := a.identity.Sign(validationData)
	packet = append(packet, signature...)

	// Add app data
	if len(a.appData) > 0 {
		packet = append(packet, a.appData...)
	}

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

	slog.Debug("Creating new announce",
		"appDataLen", len(appData),
		"hasRatchet", ratchetID != nil,
		"pathResponse", pathResponse)

	if identity == nil {
		slog.Warn("Error: nil identity provided")
		return nil, errors.New("identity cannot be nil")
	}

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	destHash := identity.Hash()
	slog.Debug("Generated destination", "hash", hex.EncodeToString(destHash))

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

	// Create initial packet
	packet := a.CreatePacket()
	a.packet = packet

	// Generate hash
	hash := a.Hash()

	slog.Debug("Created announce object",
		"destHash", hex.EncodeToString(a.destinationHash),
		"hops", a.hops,
		"announce hash", hex.EncodeToString(hash))

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
