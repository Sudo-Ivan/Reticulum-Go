package packet

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
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

type Packet struct {
	Header     [2]byte
	Addresses  []byte
	Context    byte
	Data       []byte
	AccessCode []byte
	RandomBlob []byte
}

func NewAnnouncePacket(destHash []byte, publicKey []byte, appData []byte) (*Packet, error) {
	p := &Packet{
		Header:    [2]byte{0, 0}, // Start with 0 hops
		Addresses: make([]byte, AddressSize),
		Data:      make([]byte, 0, MaxDataSize),
	}

	// Set header flags for announce packet
	p.Header[0] |= HeaderTypeFlag                                 // Single address
	p.Header[0] |= (PropagationBroadcast << 3) & PropagationFlags // Broadcast
	p.Header[0] |= (DestinationSingle << 1) & DestinationFlags    // Single destination
	p.Header[0] |= PacketTypeAnnounce & PacketTypeFlags           // Announce type

	// Set destination hash
	if len(destHash) != AddressSize {
		return nil, errors.New("invalid destination hash size")
	}
	copy(p.Addresses, destHash)

	// Build announce data
	// Public key
	p.Data = append(p.Data, publicKey...)

	// App data length and content
	appDataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(appDataLen, uint16(len(appData)))
	p.Data = append(p.Data, appDataLen...)
	p.Data = append(p.Data, appData...)

	// Add random blob
	randomBlob := make([]byte, RandomBlobSize)
	if _, err := rand.Read(randomBlob); err != nil {
		return nil, err
	}
	p.RandomBlob = randomBlob
	p.Data = append(p.Data, randomBlob...)

	return p, nil
}

func NewPacket(packetType byte, flags byte, hops byte, destKey []byte, data []byte) (*Packet, error) {
	if len(destKey) != AddressSize {
		return nil, errors.New("invalid destination key length")
	}

	p := &Packet{
		Header:    [2]byte{flags, hops},
		Addresses: make([]byte, AddressSize),
		Data:      data,
	}

	// Set packet type in flags
	p.Header[0] |= packetType & PacketTypeFlags

	// Copy destination address
	copy(p.Addresses, destKey)

	return p, nil
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
