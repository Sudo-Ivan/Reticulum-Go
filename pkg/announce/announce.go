package announce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"golang.org/x/crypto/curve25519"
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
	destinationName string
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

func New(dest *identity.Identity, destinationHash []byte, destinationName string, appData []byte, pathResponse bool, config *common.ReticulumConfig) (*Announce, error) {
	if dest == nil {
		return nil, errors.New("destination identity required")
	}

	if len(destinationHash) == 0 {
		return nil, errors.New("destination hash required")
	}

	if destinationName == "" {
		return nil, errors.New("destination name required")
	}

	a := &Announce{
		mutex:            &sync.RWMutex{},
		identity:         dest,
		destinationHash:  destinationHash,
		destinationName:  destinationName,
		appData:          appData,
		config:           config,
		hops:             0,
		timestamp:        time.Now().Unix(),
		pathResponse:     pathResponse,
		retries:          0,
		handlers:         make([]AnnounceHandler, 0),
	}

	// Get current ratchet ID if enabled
	currentRatchet := dest.GetCurrentRatchetKey()
	if currentRatchet != nil {
		ratchetPub, err := curve25519.X25519(currentRatchet, curve25519.Basepoint)
		if err == nil {
			a.ratchetID = dest.GetRatchetID(ratchetPub)
		}
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

	debug.Log(debug.DEBUG_TRACE, "Propagating announce across interfaces", "count", len(interfaces))

	var packet []byte
	if a.packet != nil {
		debug.Log(debug.DEBUG_TRACE, "Using cached packet", "bytes", len(a.packet))
		packet = a.packet
	} else {
		debug.Log(debug.DEBUG_TRACE, "Creating new packet")
		packet = a.CreatePacket()
		a.packet = packet
	}

	for _, iface := range interfaces {
		if !iface.IsEnabled() {
			debug.Log(debug.DEBUG_TRACE, "Skipping disabled interface", "name", iface.GetName())
			continue
		}
		if !iface.GetBandwidthAvailable() {
			debug.Log(debug.DEBUG_TRACE, "Skipping interface with insufficient bandwidth", "name", iface.GetName())
			continue
		}

		debug.Log(debug.DEBUG_TRACE, "Sending announce on interface", "name", iface.GetName())
		if err := iface.Send(packet, ""); err != nil {
			debug.Log(debug.DEBUG_TRACE, "Failed to send on interface", "name", iface.GetName(), "error", err)
			return fmt.Errorf("failed to propagate on interface %s: %w", iface.GetName(), err)
		}
		debug.Log(debug.DEBUG_TRACE, "Successfully sent announce on interface", "name", iface.GetName())
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

	debug.Log(debug.DEBUG_TRACE, "Handling announce packet", "bytes", len(data))

	// Minimum packet size validation
	// header(2) + desthash(16) + context(1) + enckey(32) + signkey(32) + namehash(10) +
	// randomhash(10) + signature(64) + min app data(3)
	if len(data) < 170 {
		debug.Log(debug.DEBUG_TRACE, "Invalid announce data length", "bytes", len(data), "minimum", 170)
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
		debug.Log(debug.DEBUG_TRACE, "Announce exceeded max hops", "hops", hopCount)
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

		debug.Log(debug.DEBUG_TRACE, "Header type 2 announce", "destHash", fmt.Sprintf("%x", destHash), "transportID", fmt.Sprintf("%x", transportID), "context", contextByte)
	} else {
		// Header type 1 format: header(2) + desthash(16) + context(1) + data
		if len(data) < 19 {
			return errors.New("header type 1 packet too short")
		}
		destHash := data[2:18]
		contextByte = data[18]
		packetData = data[19:]

		debug.Log(debug.DEBUG_TRACE, "Header type 1 announce", "destHash", fmt.Sprintf("%x", destHash), "context", contextByte)
	}

	// Now parse the data portion according to the spec
	// Public Key (32) + Signing Key (32) + Name Hash (10) + Random Hash (10) + Ratchet (32) + Signature (64) + App Data

	if len(packetData) < 180 { // 32 + 32 + 10 + 10 + 32 + 64
		return errors.New("announce data too short")
	}

	// Extract the components
	encKey := packetData[:32]
	signKey := packetData[32:64]
	nameHash := packetData[64:74]
	randomHash := packetData[74:84]
	ratchetData := packetData[84:116]
	signature := packetData[116:180]
	appData := packetData[180:]

	debug.Log(debug.DEBUG_TRACE, "Announce fields", "encKey", fmt.Sprintf("%x", encKey), "signKey", fmt.Sprintf("%x", signKey))
	debug.Log(debug.DEBUG_TRACE, "Name and random hash", "nameHash", fmt.Sprintf("%x", nameHash), "randomHash", fmt.Sprintf("%x", randomHash))
	debug.Log(debug.DEBUG_TRACE, "Ratchet data", "ratchet", fmt.Sprintf("%x", ratchetData[:8]))
	debug.Log(debug.DEBUG_TRACE, "Signature and app data", "signature", fmt.Sprintf("%x", signature[:8]), "appDataLen", len(appData))

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
	signedData = append(signedData, ratchetData...)
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
	// This function creates the complete announce packet according to the Reticulum specification.
	// Announce Packet Structure:
	// [Header (2 bytes)][Dest Hash (16 bytes)][Context (1 byte)][Announce Data]
	// Announce Data Structure:
	// [Public Key (64 bytes)][Name Hash (10 bytes)][Random Hash (10 bytes)][Ratchet (32 bytes optional)][Signature (64 bytes)][App Data]

	// 2. Destination Hash
	destHash := a.destinationHash
	if len(destHash) > 16 {
		destHash = destHash[:16]
	}

	// 3. Announce Data
	// 3.1 Public Key (full 64 bytes - not split into enc/sign keys in packet)
	pubKey := a.identity.GetPublicKey()
	if len(pubKey) != 64 {
		debug.Log(debug.DEBUG_TRACE, "Invalid public key length", "expected", 64, "got", len(pubKey))
	}

	// 3.2 Name Hash
	nameHash := sha256.Sum256([]byte(a.destinationName))
	nameHash10 := nameHash[:10]

	// 3.3 Random Hash (5 bytes random + 5 bytes timestamp)
	randomHash := make([]byte, 10)
	_, err := rand.Read(randomHash[:5])
	if err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to read random bytes for announce", "error", err)
	}
	// Add 5 bytes of timestamp
	timeBytes := make([]byte, 8)
	// #nosec G115 - Unix timestamp is always positive, no overflow risk
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))
	copy(randomHash[5:], timeBytes[:5])

	// 3.4 Ratchet (only include if exists)
	var ratchetData []byte
	currentRatchetKey := a.identity.GetCurrentRatchetKey()
	if currentRatchetKey != nil {
		ratchetPub, err := curve25519.X25519(currentRatchetKey, curve25519.Basepoint)
		if err == nil {
			ratchetData = make([]byte, 32)
			copy(ratchetData, ratchetPub)
		}
	}
	
	// Determine context flag based on whether ratchet exists
	contextFlag := byte(0)
	if len(ratchetData) > 0 {
		contextFlag = 1 // FLAG_SET
	}

	// 1. Create Header - Use HEADER_TYPE_1
	header := CreateHeader(
		IFAC_NONE,
		HEADER_TYPE_1,
		contextFlag,
		PROP_TYPE_BROADCAST,
		DEST_TYPE_SINGLE,
		PACKET_TYPE_ANNOUNCE,
		a.hops,
	)

	// 4. Context Byte
	contextByte := byte(0)
	if a.pathResponse {
		contextByte = 0x0B // PATH_RESPONSE context
	}

	// 3.5 Signature
	// The signature is calculated over: Dest Hash + Public Key (64 bytes) + Name Hash + Random Hash + Ratchet (if exists) + App Data
	validationData := make([]byte, 0)
	validationData = append(validationData, destHash...)
	validationData = append(validationData, pubKey...)
	validationData = append(validationData, nameHash10...)
	validationData = append(validationData, randomHash...)
	if len(ratchetData) > 0 {
		validationData = append(validationData, ratchetData...)
	}
	validationData = append(validationData, a.appData...)
	signature := a.identity.Sign(validationData)

	debug.Log(debug.DEBUG_TRACE, "Creating announce packet", "destHash", fmt.Sprintf("%x", destHash), "pubKeyLen", len(pubKey), "nameHash", fmt.Sprintf("%x", nameHash10), "randomHash", fmt.Sprintf("%x", randomHash), "ratchetLen", len(ratchetData), "sigLen", len(signature), "appDataLen", len(a.appData))

	// 5. Assemble the packet (HEADER_TYPE_1 format)
	packet := make([]byte, 0)
	packet = append(packet, header...)
	packet = append(packet, destHash...)
	packet = append(packet, contextByte)
	packet = append(packet, pubKey...)
	packet = append(packet, nameHash10...)
	packet = append(packet, randomHash...)
	if len(ratchetData) > 0 {
		packet = append(packet, ratchetData...)
	}
	packet = append(packet, signature...)
	packet = append(packet, a.appData...)

	debug.Log(debug.DEBUG_TRACE, "Final announce packet", "totalBytes", len(packet), "ratchetLen", len(ratchetData), "appDataLen", len(a.appData))

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
func NewAnnounce(identity *identity.Identity, destinationHash []byte, appData []byte, ratchetID []byte, pathResponse bool, config *common.ReticulumConfig) (*Announce, error) {
	debug.Log(debug.DEBUG_TRACE, "Creating new announce", "destHash", fmt.Sprintf("%x", destinationHash), "appDataLen", len(appData), "hasRatchet", ratchetID != nil, "pathResponse", pathResponse)

	if identity == nil {
		debug.Log(debug.DEBUG_ERROR, "Nil identity provided")
		return nil, errors.New("identity cannot be nil")
	}

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	if len(destinationHash) == 0 {
		return nil, errors.New("destination hash cannot be empty")
	}

	destHash := destinationHash
	debug.Log(debug.DEBUG_TRACE, "Using provided destination hash", "destHash", fmt.Sprintf("%x", destHash))

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

	debug.Log(debug.DEBUG_TRACE, "Created announce object", "destHash", fmt.Sprintf("%x", a.destinationHash), "hops", a.hops)

	// Create initial packet
	packet := a.CreatePacket()
	a.packet = packet

	// Generate hash
	hash := a.Hash()
	debug.Log(debug.DEBUG_TRACE, "Generated announce hash", "hash", fmt.Sprintf("%x", hash))

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
