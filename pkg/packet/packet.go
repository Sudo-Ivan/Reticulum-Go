package packet

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize    = 2
	AddressSize   = 16
	ContextSize   = 1
	MaxDataSize   = 465 // Maximum size of payload data
)

// Header flags and types
const (
	// First byte flags
	IFACFlag         = 0x80 // Interface authentication code flag
	HeaderTypeFlag   = 0x40 // Header type flag
	ContextFlag      = 0x20 // Context flag
	PropagationFlags = 0x18 // Propagation type flags (bits 3-4)
	DestinationFlags = 0x06 // Destination type flags (bits 1-2)
	PacketTypeFlags  = 0x01 // Packet type flags (bit 0)

	// Second byte
	HopsField = 0xFF // Number of hops (entire byte)
)

type Packet struct {
	Header      [2]byte
	Addresses   []byte // Either 16 or 32 bytes depending on header type
	Context     byte
	Data        []byte
	AccessCode  []byte // Optional: Only present if IFAC flag is set
}

func NewPacket(headerType, propagationType, destinationType, packetType byte, hops byte) *Packet {
	p := &Packet{
		Header:    [2]byte{0, hops},
		Addresses: make([]byte, 0),
		Data:     make([]byte, 0),
	}

	// Set header type
	if headerType == HeaderType2 {
		p.Header[0] |= HeaderTypeFlag
		p.Addresses = make([]byte, 2*AddressSize) // Two address fields
	} else {
		p.Addresses = make([]byte, AddressSize) // One address field
	}

	// Set propagation type
	p.Header[0] |= (propagationType << 3) & PropagationFlags

	// Set destination type
	p.Header[0] |= (destinationType << 1) & DestinationFlags

	// Set packet type
	p.Header[0] |= packetType & PacketTypeFlags

	return p
}

func (p *Packet) SetAccessCode(code []byte) {
	p.AccessCode = code
	p.Header[0] |= IFACFlag
}

func (p *Packet) SetContext(context byte) {
	p.Context = context
	p.Header[0] |= ContextFlag
}

func (p *Packet) SetData(data []byte) error {
	if len(data) > MaxDataSize {
		return errors.New("data exceeds maximum allowed size")
	}
	p.Data = data
	return nil
}

func (p *Packet) SetAddress(index int, address []byte) error {
	if len(address) != AddressSize {
		return errors.New("invalid address size")
	}
	
	offset := index * AddressSize
	if offset+AddressSize > len(p.Addresses) {
		return errors.New("address index out of range")
	}
	
	copy(p.Addresses[offset:], address)
	return nil
}

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

func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("packet data too short")
	}

	p := &Packet{
		Header: [2]byte{data[0], data[1]},
	}

	offset := HeaderSize

	// Handle access code if present
	if p.Header[0]&IFACFlag != 0 {
		// Access code handling would go here
		// For now, we'll assume no access code
		return nil, errors.New("access code handling not implemented")
	}

	// Determine address size based on header type
	addrLen := AddressSize
	if p.Header[0]&HeaderTypeFlag != 0 {
		addrLen = 2 * AddressSize
	}

	if len(data[offset:]) < addrLen+ContextSize {
		return nil, errors.New("packet data too short for addresses and context")
	}

	// Copy addresses
	p.Addresses = make([]byte, addrLen)
	copy(p.Addresses, data[offset:offset+addrLen])
	offset += addrLen

	// Copy context
	p.Context = data[offset]
	offset++

	// Copy remaining data
	p.Data = make([]byte, len(data)-offset)
	copy(p.Data, data[offset:])

	return p, nil
} 