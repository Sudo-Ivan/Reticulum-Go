package packet

import (
	"crypto/sha256"
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

	// Create header byte
	flags := byte(p.HeaderType<<6) | byte(p.ContextFlag<<5) |
		byte(p.TransportType<<4) | byte(p.DestinationType<<2) | byte(p.PacketType)

	header := []byte{flags, p.Hops}
	log.Printf("[DEBUG-5] Created packet header: flags=%08b, hops=%d", flags, p.Hops)

	if p.HeaderType == HeaderType2 {
		if p.TransportID == nil {
			return errors.New("transport ID required for header type 2")
		}
		header = append(header, p.TransportID...)
		log.Printf("[DEBUG-7] Added transport ID to header: %x", p.TransportID)
	}

	header = append(header, p.DestinationHash...)
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
		if len(p.Raw) < 2*dstLen+3 {
			return errors.New("packet too short for header type 2")
		}
		p.TransportID = p.Raw[2 : dstLen+2]
		p.DestinationHash = p.Raw[dstLen+2 : 2*dstLen+2]
		p.Context = p.Raw[2*dstLen+2]
		p.Data = p.Raw[2*dstLen+3:]
	} else {
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
	hashable := []byte{p.Raw[0] & 0b00001111}
	if p.HeaderType == HeaderType2 {
		hashable = append(hashable, p.Raw[18:]...)
	} else {
		hashable = append(hashable, p.Raw[2:]...)
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
	log.Printf("[DEBUG-7] Creating new announce packet: destHash=%x, appData=%s", destHash, string(appData))

	// Create combined public key
	pubKey := identity.GetPublicKey()
	log.Printf("[DEBUG-6] Using public key: %x", pubKey)

	// Create signed data
	signedData := append(destHash, pubKey...)
	signedData = append(signedData, appData...)
	log.Printf("[DEBUG-5] Created signed data (%d bytes)", len(signedData))

	// Sign the data
	signature := identity.Sign(signedData)
	log.Printf("[DEBUG-6] Generated signature: %x", signature)

	// Combine all data
	data := append(pubKey, appData...)
	data = append(data, signature...)
	log.Printf("[DEBUG-5] Combined packet data (%d bytes)", len(data))

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
