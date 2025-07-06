package announce

import (
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

	// Minimum packet size validation
	// header(2) + desthash(16) + context(1) + enckey(32) + signkey(32) + namehash(10) +
	// randomhash(10) + signature(64) + min app data(3)
	if len(data) < 170 {
		log.Printf("[DEBUG-7] Invalid announce data length: %d bytes (minimum 170)", len(data))
		return errors.New("invalid announce data length")
	}

	// Extract header and check packet type
	header := data[:2]
	if header[0]&0x03 != PACKET_TYPE_ANNOUNCE {
		return errors.New("not an announce packet")
	}

	// Get hop count
	hopCount := header[1]
	if hopCount > MAX_HOPS {
		log.Printf("[DEBUG-7] Announce exceeded max hops: %d", hopCount)
		return errors.New("announce exceeded maximum hop count")
	}

	// Parse the packet based on header type
	headerType := (header[0] & 0b01000000) >> 6
	var contextByte byte
	var packetData []byte

	if headerType == HEADER_TYPE_2 {
		// Header type 2 format: header(2) + desthash(16) + transportid(16) + context(1) + data
		if len(data) < 35 {
			return errors.New("header type 2 packet too short")
		}
		destHash := data[2:18]
		transportID := data[18:34]
		contextByte = data[34]
		packetData = data[35:]

		log.Printf("[DEBUG-7] Header type 2 announce: destHash=%x, transportID=%x, context=%d",
			destHash, transportID, contextByte)
	} else {
		// Header type 1 format: header(2) + desthash(16) + context(1) + data
		if len(data) < 19 {
			return errors.New("header type 1 packet too short")
		}
		destHash := data[2:18]
		contextByte = data[18]
		packetData = data[19:]

		log.Printf("[DEBUG-7] Header type 1 announce: destHash=%x, context=%d",
			destHash, contextByte)
	}

	// Now parse the data portion according to the spec
	// Public Key (32) + Signing Key (32) + Name Hash (10) + Random Hash (10) + [Ratchet] + Signature (64) + App Data

	if len(packetData) < 148 { // 32 + 32 + 10 + 10 + 64
		return errors.New("announce data too short")
	}

	// Extract the components
	encKey := packetData[:32]
	signKey := packetData[32:64]
	nameHash := packetData[64:74]
	randomHash := packetData[74:84]

	// The next field could be a ratchet (32 bytes) or signature (64 bytes)
	// We need to detect this somehow or use a flag
	// For now, assume no ratchet

	signature := packetData[84:148]
	appData := packetData[148:]

	log.Printf("[DEBUG-7] Announce fields: encKey=%x, signKey=%x", encKey, signKey)
	log.Printf("[DEBUG-7] Name hash=%x, random hash=%x", nameHash, randomHash)
	log.Printf("[DEBUG-7] Signature=%x, appDataLen=%d", signature[:8], len(appData))

	// Get the destination hash from header
	var destHash []byte
	if headerType == HEADER_TYPE_2 {
		destHash = data[2:18]
	} else {
		destHash = data[2:18]
	}

	// Combine public keys
	pubKey := append(encKey, signKey...)

	// Create announced identity from public keys
	announcedIdentity := identity.FromPublicKey(pubKey)
	if announcedIdentity == nil {
		return errors.New("invalid identity public key")
	}

	// Verify signature
	signedData := make([]byte, 0)
	signedData = append(signedData, destHash...)
	signedData = append(signedData, encKey...)
	signedData = append(signedData, signKey...)
	signedData = append(signedData, nameHash...)
	signedData = append(signedData, randomHash...)
	signedData = append(signedData, appData...)

	if !announcedIdentity.Verify(signedData, signature) {
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
		HEADER_TYPE_2, // Use header type 2 for announces
		0,             // No context flag
		PROP_TYPE_BROADCAST,
		DEST_TYPE_SINGLE,
		PACKET_TYPE_ANNOUNCE,
		a.hops,
	)

	packet := header

	// Add destination hash (16 bytes)
	packet = append(packet, a.destinationHash...)

	// If using header type 2, add transport ID (16 bytes)
	// For broadcast announces, this is filled with zeroes
	transportID := make([]byte, 16)
	packet = append(packet, transportID...)

	// Add context byte
	packet = append(packet, byte(0)) // Context byte, 0 for announces

	// Add public key parts (32 bytes each)
	pubKey := a.identity.GetPublicKey()
	encKey := pubKey[:32]  // Encryption key
	signKey := pubKey[32:] // Signing key

	// Start building data portion according to spec
	data := make([]byte, 0, 32+32+10+10+32+64+len(a.appData))
	data = append(data, encKey...)  // Encryption key (32 bytes)
	data = append(data, signKey...) // Signing key (32 bytes)

	// Determine if this is a node announce based on appData format
	var appName string
	if len(a.appData) > 2 && a.appData[0] == 0x93 {
		// This is a node announcement
		appName = "reticulum.node"
	} else if len(a.appData) > 3 && a.appData[0] == 0x92 && a.appData[1] == 0xc4 {
		nameLen := int(a.appData[2])
		if 3+nameLen <= len(a.appData) {
			appName = string(a.appData[3 : 3+nameLen])
		} else {
			appName = fmt.Sprintf("%s.%s", a.config.AppName, a.config.AppAspect)
		}
	} else {
		// Default fallback using config values
		appName = fmt.Sprintf("%s.%s", a.config.AppName, a.config.AppAspect)
	}

	// Add name hash (10 bytes)
	nameHash := sha256.Sum256([]byte(appName))
	nameHash10 := nameHash[:10]
	log.Printf("[DEBUG-6] Using name hash for '%s': %x", appName, nameHash10)
	data = append(data, nameHash10...)

	// Add random hash (10 bytes) - 5 bytes random + 5 bytes time
	randomHash := make([]byte, 10)
	_, err := rand.Read(randomHash[:5]) // #nosec G104
	if err != nil {
		log.Printf("[DEBUG-7] Failed to read random bytes for hash: %v", err)
		return nil // Or handle the error appropriately
	}
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix())) // #nosec G115
	copy(randomHash[5:], timeBytes[:5])
	data = append(data, randomHash...)

	// Add ratchet ID (32 bytes) - required in the packet format
	if a.ratchetID != nil {
		data = append(data, a.ratchetID...)
	} else {
		// If there's no ratchet, add 32 zero bytes as placeholder
		data = append(data, make([]byte, 32)...)
	}

	// Create validation data for signature
	// Signature consists of destination hash, public keys, name hash, random hash, and app data
	validationData := make([]byte, 0)
	validationData = append(validationData, a.destinationHash...)
	validationData = append(validationData, encKey...)
	validationData = append(validationData, signKey...)
	validationData = append(validationData, nameHash10...)
	validationData = append(validationData, randomHash...)
	validationData = append(validationData, a.appData...)

	// Add signature (64 bytes)
	signature := a.identity.Sign(validationData)
	data = append(data, signature...)

	// Add app data
	if len(a.appData) > 0 {
		data = append(data, a.appData...)
	}

	// Combine header and data
	packet = append(packet, data...)

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
	binary.BigEndian.PutUint16(appDataLen, uint16(len(appData))) // #nosec G115
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
		// Use CreatePacket to generate the packet
		a.packet = a.CreatePacket()
	}

	return a.packet
}
