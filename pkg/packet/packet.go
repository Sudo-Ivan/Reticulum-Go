package packet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
)

const (
	// Packet Types
	PacketTypeData     = 0x00
	PacketTypeAnnounce = 0x01
	PacketTypeLinkReq  = 0x02
	PacketTypeProof    = 0x03

	// Header Types
	HeaderType1 = 0x00
	HeaderType2 = 0x01

	// Context Types
	ContextNone         = 0x00
	ContextResource     = 0x01
	ContextResourceAdv  = 0x02
	ContextResourceReq  = 0x03
	ContextResourceHMU  = 0x04
	ContextResourcePRF  = 0x05
	ContextResourceICL  = 0x06
	ContextResourceRCL  = 0x07
	ContextCacheReq     = 0x08
	ContextRequest      = 0x09
	ContextResponse     = 0x0A
	ContextPathResponse = 0x0B
	ContextCommand      = 0x0C
	ContextCmdStatus    = 0x0D
	ContextChannel      = 0x0E
	ContextKeepalive    = 0xFA
	ContextLinkIdentify = 0xFB
	ContextLinkClose    = 0xFC
	ContextLinkProof    = 0xFD
	ContextLRRTT        = 0xFE
	ContextLRProof      = 0xFF

	// Flag Values
	FlagSet   = 0x01
	FlagUnset = 0x00

	// Header sizes
	HeaderMaxSize = 64
	MTU           = 500

	AddressSize = 32 // Size of address/hash fields in bytes
)

type Packet struct {
	HeaderType    byte
	PacketType    byte
	TransportType byte
	Context       byte
	ContextFlag   byte
	Hops          byte

	DestinationType byte
	DestinationHash []byte
	TransportID     []byte
	Data            []byte

	Raw           []byte
	Packed        bool
	Sent          bool
	CreateReceipt bool
	FromPacked    bool

	SentAt     time.Time
	PacketHash []byte
	RatchetID  []byte

	RSSI *float64
	SNR  *float64
	Q    *float64

	Addresses []byte
}

func NewPacket(destType byte, data []byte, packetType byte, context byte,
	transportType byte, headerType byte, transportID []byte, createReceipt bool,
	contextFlag byte) *Packet {

	return &Packet{
		HeaderType:      headerType,
		PacketType:      packetType,
		TransportType:   transportType,
		Context:         context,
		ContextFlag:     contextFlag,
		Hops:            0,
		DestinationType: destType,
		Data:            data,
		TransportID:     transportID,
		CreateReceipt:   createReceipt,
		Packed:          false,
		Sent:            false,
		FromPacked:      false,
	}
}

func (p *Packet) Pack() error {
	if p.Packed {
		return nil
	}

	log.Printf("[DEBUG-6] Packing packet: type=%d, header=%d", p.PacketType, p.HeaderType)

	// Create header byte (Corrected order)
	flags := byte(0)
	flags |= (p.HeaderType << 6) & 0b01000000
	flags |= (p.ContextFlag << 5) & 0b00100000
	flags |= (p.TransportType << 4) & 0b00010000
	flags |= (p.DestinationType << 2) & 0b00001100
	flags |= p.PacketType & 0b00000011

	header := []byte{flags, p.Hops}
	log.Printf("[DEBUG-5] Created packet header: flags=%08b, hops=%d", flags, p.Hops)

	header = append(header, p.DestinationHash...)
	
	if p.HeaderType == HeaderType2 {
		if p.TransportID == nil {
			return errors.New("transport ID required for header type 2")
		}
		header = append(header, p.TransportID...)
		log.Printf("[DEBUG-7] Added transport ID to header: %x", p.TransportID)
	}

	header = append(header, p.Context)
	log.Printf("[DEBUG-6] Final header length: %d bytes", len(header))

	p.Raw = append(header, p.Data...)
	log.Printf("[DEBUG-5] Final packet size: %d bytes", len(p.Raw))

	if len(p.Raw) > MTU {
		return errors.New("packet size exceeds MTU")
	}

	p.Packed = true
	p.updateHash()
	log.Printf("[DEBUG-7] Packet hash: %x", p.PacketHash)
	return nil
}

func (p *Packet) Unpack() error {
	if len(p.Raw) < 3 {
		return errors.New("packet too short")
	}

	flags := p.Raw[0]
	p.Hops = p.Raw[1]

	p.HeaderType = (flags & 0b01000000) >> 6
	p.ContextFlag = (flags & 0b00100000) >> 5
	p.TransportType = (flags & 0b00010000) >> 4
	p.DestinationType = (flags & 0b00001100) >> 2
	p.PacketType = flags & 0b00000011

	dstLen := 16 // Truncated hash length

	if p.HeaderType == HeaderType2 {
		// Header Type 2: Header(2) + DestHash(16) + TransportID(16) + Context(1) + Data
		if len(p.Raw) < 2*dstLen+3 {
			return errors.New("packet too short for header type 2")
		}
		p.DestinationHash = p.Raw[2 : dstLen+2]           // Destination hash first
		p.TransportID = p.Raw[dstLen+2 : 2*dstLen+2]      // Transport ID second
		p.Context = p.Raw[2*dstLen+2]
		p.Data = p.Raw[2*dstLen+3:]
	} else {
		// Header Type 1: Header(2) + DestHash(16) + Context(1) + Data
		if len(p.Raw) < dstLen+3 {
			return errors.New("packet too short for header type 1")
		}
		p.TransportID = nil
		p.DestinationHash = p.Raw[2 : dstLen+2]
		p.Context = p.Raw[dstLen+2]
		p.Data = p.Raw[dstLen+3:]
	}

	p.Packed = false
	p.updateHash()
	return nil
}

func (p *Packet) GetHash() []byte {
	hashable := p.getHashablePart()
	hash := sha256.Sum256(hashable)
	return hash[:]
}

func (p *Packet) getHashablePart() []byte {
	hashable := []byte{p.Raw[0] & 0b00001111} // Lower 4 bits of flags
	if p.HeaderType == HeaderType2 {
		// Match Python: Start hash from DestHash (index 18), skipping TransportID
		dstLen := 16 // RNS.Identity.TRUNCATED_HASHLENGTH / 8
		startIndex := dstLen + 2
		if len(p.Raw) > startIndex {
			hashable = append(hashable, p.Raw[startIndex:]...)
		}
	} else {
		// Match Python: Start hash from DestHash (index 2)
		if len(p.Raw) > 2 {
			hashable = append(hashable, p.Raw[2:]...)
		}
	}
	return hashable
}

func (p *Packet) updateHash() {
	p.PacketHash = p.GetHash()
}

func (p *Packet) Serialize() ([]byte, error) {
	if !p.Packed {
		if err := p.Pack(); err != nil {
			return nil, fmt.Errorf("failed to pack packet: %w", err)
		}
	}

	p.Addresses = p.DestinationHash

	return p.Raw, nil
}

func NewAnnouncePacket(destHash []byte, identity *identity.Identity, appData []byte, transportID []byte) (*Packet, error) {
	log.Printf("[DEBUG-7] Creating new announce packet: destHash=%x, appData=%s", destHash, fmt.Sprintf("%x", appData))

	// Get public key separated into encryption and signing keys
	pubKey := identity.GetPublicKey()
	encKey := pubKey[:32]
	signKey := pubKey[32:]
	log.Printf("[DEBUG-6] Using public keys: encKey=%x, signKey=%x", encKey, signKey)

	// Parse app name from first msgpack element if possible
	// For nodes, we'll use "reticulum.node" as the name hash
	var appName string
	if len(appData) > 2 && appData[0] == 0x93 {
		// This is a node announce, use standard node name
		appName = "reticulum.node"
	} else if len(appData) > 3 && appData[0] == 0x92 && appData[1] == 0xc4 {
		// Try to extract name from peer announce appData
		nameLen := int(appData[2])
		if 3+nameLen <= len(appData) {
			appName = string(appData[3 : 3+nameLen])
		} else {
			// Default fallback
			appName = "reticulum-go.node"
		}
	} else {
		// Default fallback
		appName = "reticulum-go.node"
	}

	// Create name hash (10 bytes)
	nameHash := sha256.Sum256([]byte(appName))
	nameHash10 := nameHash[:10]
	log.Printf("[DEBUG-6] Using name hash for '%s': %x", appName, nameHash10)

	// Create random hash (10 bytes) - 5 bytes random + 5 bytes time
	randomHash := make([]byte, 10)
	_, err := rand.Read(randomHash[:5]) // #nosec G104
	if err != nil {
		log.Printf("[DEBUG-6] Failed to read random bytes for hash: %v", err)
		return nil, err // Or handle the error appropriately
	}
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix())) // #nosec G115
	copy(randomHash[5:], timeBytes[:5])
	log.Printf("[DEBUG-6] Generated random hash: %x", randomHash)

	// Prepare ratchet ID if available (not yet implemented)
	var ratchetID []byte

	// Prepare data for signature
	// Signature consists of destination hash, public keys, name hash, random hash, and app data
	signedData := make([]byte, 0, len(destHash)+len(encKey)+len(signKey)+len(nameHash10)+len(randomHash)+len(appData))
	signedData = append(signedData, destHash...)
	signedData = append(signedData, encKey...)
	signedData = append(signedData, signKey...)
	signedData = append(signedData, nameHash10...)
	signedData = append(signedData, randomHash...)
	signedData = append(signedData, appData...)
	log.Printf("[DEBUG-5] Created signed data (%d bytes)", len(signedData))

	// Sign the data
	signature := identity.Sign(signedData)
	log.Printf("[DEBUG-6] Generated signature: %x", signature)

	// Combine all fields according to spec
	// Data structure: Public Key (32) + Signing Key (32) + Name Hash (10) + Random Hash (10) + Ratchet (optional) + Signature (64) + App Data
	data := make([]byte, 0, 32+32+10+10+64+len(appData))
	data = append(data, encKey...)     // Encryption key (32 bytes)
	data = append(data, signKey...)    // Signing key (32 bytes)
	data = append(data, nameHash10...) // Name hash (10 bytes)
	data = append(data, randomHash...) // Random hash (10 bytes)
	if ratchetID != nil {
		data = append(data, ratchetID...) // Ratchet ID (32 bytes if present)
	}
	data = append(data, signature...) // Signature (64 bytes)
	data = append(data, appData...)   // Application data (variable)

	log.Printf("[DEBUG-5] Combined packet data (%d bytes)", len(data))

	// Create the packet with header type 2 (two address fields)
	p := &Packet{
		HeaderType:      HeaderType2,
		PacketType:      PacketTypeAnnounce,
		TransportID:     transportID,
		DestinationHash: destHash,
		Data:            data,
	}

	log.Printf("[DEBUG-4] Created announce packet: type=%d, header=%d", p.PacketType, p.HeaderType)
	return p, nil
}
