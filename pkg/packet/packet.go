package packet

import (
	"errors"
	"time"
)

const (
	// Packet Types
	PacketTypeData       = 0x00
	PacketTypeAnnounce   = 0x01
	PacketTypeLink       = 0x02
	PacketTypeProof      = 0x03
	PACKET_TYPE_DATA     = 0x00
	PACKET_TYPE_LINK     = 0x01
	PACKET_TYPE_IDENTIFY = 0x02

	// Sizes
	HeaderSize     = 2
	AddressSize    = 16
	ContextSize    = 1
	MaxDataSize    = 465
	RandomBlobSize = 16
)

// Header flags and types
const (
	// First byte flags
	IFACFlag         = 0x80
	HeaderTypeFlag   = 0x40
	ContextFlag      = 0x20
	PropagationFlags = 0x18
	DestinationFlags = 0x06
	PacketTypeFlags  = 0x01

	// Second byte
	HopsField = 0xFF
)

// Packet represents a network packet in the Reticulum protocol
type Packet struct {
	Header     [2]byte
	Addresses  []byte
	Context    byte
	Data       []byte
	AccessCode []byte
	RandomBlob []byte
	Timestamp  time.Time
}

// NewPacket creates a new packet with the specified parameters
func NewPacket(packetType byte, flags byte, hops byte, destKey []byte, data []byte) (*Packet, error) {
	if len(destKey) != AddressSize {
		return nil, errors.New("invalid destination key length")
	}

	p := &Packet{
		Header:    [2]byte{flags, hops},
		Addresses: make([]byte, AddressSize),
		Data:      data,
		Timestamp: time.Now(),
	}

	// Set packet type in flags
	p.Header[0] |= packetType & PacketTypeFlags

	// Copy destination address
	copy(p.Addresses, destKey)

	return p, nil
}

// Serialize converts the packet into a byte slice
func (p *Packet) Serialize() ([]byte, error) {
	totalSize := HeaderSize + len(p.Addresses) + ContextSize + len(p.Data)
	if p.AccessCode != nil {
		totalSize += len(p.AccessCode)
	}

	buffer := make([]byte, totalSize)
	offset := 0

	// Write header
	copy(buffer[offset:], p.Header[:])
	offset += HeaderSize

	// Write access code if present
	if p.AccessCode != nil {
		copy(buffer[offset:], p.AccessCode)
		offset += len(p.AccessCode)
	}

	// Write addresses
	copy(buffer[offset:], p.Addresses)
	offset += len(p.Addresses)

	// Write context
	buffer[offset] = p.Context
	offset += ContextSize

	// Write data
	copy(buffer[offset:], p.Data)

	return buffer, nil
}

type AnnouncePacket struct {
	Header      [2]byte
	DestHash    []byte
	PublicKey   []byte
	AppData     []byte
	RandomBlob  []byte
	Signature   []byte
	HopCount    byte
	Timestamp   time.Time
}
