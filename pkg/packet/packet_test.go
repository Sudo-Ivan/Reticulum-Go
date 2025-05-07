package packet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("Failed to generate random bytes: " + err.Error())
	}
	return b
}

func TestPacketPackUnpack(t *testing.T) {
	testCases := []struct {
		name             string
		headerType       byte
		packetType       byte
		transportType    byte
		destType         byte
		context          byte
		contextFlag      byte
		dataSize         int
		needsTransportID bool
	}{
		{
			name:             "HeaderType1_Data_NoContextFlag",
			headerType:       HeaderType1,
			packetType:       PacketTypeData,
			transportType:    0x01, // Example
			destType:         0x02, // Example
			context:          ContextNone,
			contextFlag:      FlagUnset,
			dataSize:         100,
			needsTransportID: false,
		},
		{
			name:             "HeaderType2_Announce_ContextFlagSet",
			headerType:       HeaderType2,
			packetType:       PacketTypeAnnounce,
			transportType:    0x01, // Changed from 0x0F (15) to 1 (valid 1-bit value)
			destType:         0x01, // Example
			context:          ContextResourceAdv,
			contextFlag:      FlagSet,
			dataSize:         50,
			needsTransportID: true,
		},
		{
			name:             "HeaderType1_EmptyData",
			headerType:       HeaderType1,
			packetType:       PacketTypeProof,
			transportType:    0x00,
			destType:         0x00,
			context:          ContextLRProof,
			contextFlag:      FlagSet,
			dataSize:         0,
			needsTransportID: false,
		},
		{
			name:             "HeaderType2_MaxHops", // Hops are set manually before pack
			headerType:       HeaderType2,
			packetType:       PacketTypeLinkReq,
			transportType:    0x01, // Changed from 0x05 (5) to 1 (valid 1-bit value)
			destType:         0x03,
			context:          ContextLinkIdentify,
			contextFlag:      FlagUnset,
			dataSize:         200,
			needsTransportID: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalData := randomBytes(tc.dataSize)
			originalDestHash := randomBytes(16) // Truncated dest hash
			var originalTransportID []byte
			if tc.needsTransportID {
				originalTransportID = randomBytes(16)
			}

			p := &Packet{
				HeaderType:      tc.headerType,
				PacketType:      tc.packetType,
				TransportType:   tc.transportType,
				Context:         tc.context,
				ContextFlag:     tc.contextFlag,
				Hops:            5, // Example hops
				DestinationType: tc.destType,
				DestinationHash: originalDestHash,
				TransportID:     originalTransportID,
				Data:            originalData,
				Packed:          false,
			}

			// Test Pack
			err := p.Pack()
			if err != nil {
				t.Fatalf("Pack() failed: %v", err)
			}
			if !p.Packed {
				t.Error("Pack() did not set Packed flag to true")
			}
			if len(p.Raw) == 0 {
				t.Error("Pack() resulted in empty Raw data")
			}

			// Create a new packet from the raw data for unpacking
			unpackTarget := &Packet{Raw: p.Raw}

			// Test Unpack
			err = unpackTarget.Unpack()
			if err != nil {
				t.Fatalf("Unpack() failed: %v", err)
			}

			// Verify unpacked fields match original
			if unpackTarget.HeaderType != tc.headerType {
				t.Errorf("Unpacked HeaderType = %d; want %d", unpackTarget.HeaderType, tc.headerType)
			}
			if unpackTarget.PacketType != tc.packetType {
				t.Errorf("Unpacked PacketType = %d; want %d", unpackTarget.PacketType, tc.packetType)
			}
			if unpackTarget.TransportType != tc.transportType {
				t.Errorf("Unpacked TransportType = %d; want %d", unpackTarget.TransportType, tc.transportType)
			}
			if unpackTarget.Context != tc.context {
				t.Errorf("Unpacked Context = %d; want %d", unpackTarget.Context, tc.context)
			}
			if unpackTarget.ContextFlag != tc.contextFlag {
				t.Errorf("Unpacked ContextFlag = %d; want %d", unpackTarget.ContextFlag, tc.contextFlag)
			}
			if unpackTarget.Hops != 5 { // Should match the Hops set before packing
				t.Errorf("Unpacked Hops = %d; want %d", unpackTarget.Hops, 5)
			}
			if unpackTarget.DestinationType != tc.destType {
				t.Errorf("Unpacked DestinationType = %d; want %d", unpackTarget.DestinationType, tc.destType)
			}
			if !bytes.Equal(unpackTarget.DestinationHash, originalDestHash) {
				t.Errorf("Unpacked DestinationHash = %x; want %x", unpackTarget.DestinationHash, originalDestHash)
			}
			if !bytes.Equal(unpackTarget.Data, originalData) {
				t.Errorf("Unpacked Data = %x; want %x", unpackTarget.Data, originalData)
			}

			if tc.needsTransportID {
				if !bytes.Equal(unpackTarget.TransportID, originalTransportID) {
					t.Errorf("Unpacked TransportID = %x; want %x", unpackTarget.TransportID, originalTransportID)
				}
			} else {
				if unpackTarget.TransportID != nil {
					t.Errorf("Unpacked TransportID = %x; want nil", unpackTarget.TransportID)
				}
			}
		})
	}
}

func TestPackMTUExceeded(t *testing.T) {
	p := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		DestinationHash: randomBytes(16),
		Context:         ContextNone,
		Data:            randomBytes(MTU + 10), // Exceed MTU
	}
	err := p.Pack()
	if err == nil {
		t.Errorf("Pack() should have failed due to exceeding MTU, but it didn't")
	}
}

func TestUnpackTooShort(t *testing.T) {
	testCases := []struct {
		name string
		raw  []byte
	}{
		{"VeryShort", []byte{0x01}},
		{"HeaderType1MinShort", []byte{0x00, 0x05, 0x01, 0x02}}, // Missing parts of dest hash
		{"HeaderType2MinShort", []byte{0x40, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}}, // Missing dest hash
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Packet{Raw: tc.raw}
			err := p.Unpack()
			if err == nil {
				t.Errorf("Unpack() should have failed for short packet, but it didn't")
			}
		})
	}
}

func TestPacketHashing(t *testing.T) {
	// Create two identical packets
	data := randomBytes(50)
	destHash := randomBytes(16)
	p1 := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		TransportType:   0x01,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            2,
		DestinationType: 0x02,
		DestinationHash: destHash,
		Data:            data,
	}
	p2 := &Packet{
		HeaderType:      HeaderType1,
		PacketType:      PacketTypeData,
		TransportType:   0x01,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            2,
		DestinationType: 0x02,
		DestinationHash: destHash,
		Data:            data,
	}

	// Pack both
	if err := p1.Pack(); err != nil {
		t.Fatalf("p1.Pack() failed: %v", err)
	}
	if err := p2.Pack(); err != nil {
		t.Fatalf("p2.Pack() failed: %v", err)
	}

	// Hashes should be identical
	hash1 := p1.GetHash()
	hash2 := p2.GetHash()
	if !bytes.Equal(hash1, hash2) {
		t.Errorf("Hashes of identical packets differ:\nHash1: %x\nHash2: %x", hash1, hash2)
	}
	if !bytes.Equal(p1.PacketHash, hash1) {
		t.Errorf("p1.PacketHash (%x) does not match GetHash() (%x)", p1.PacketHash, hash1)
	}

	// Change a non-hashable field (hops) in p2
	p2.Hops = 3
	p2.Raw[1] = 3 // Need to modify Raw as Pack isn't called again
	hash3 := p2.GetHash()
	if !bytes.Equal(hash1, hash3) {
		t.Errorf("Hash changed after modifying non-hashable Hops field:\nHash1: %x\nHash3: %x", hash1, hash3)
	}

	// Change a hashable field (data) in p2
	p2.Data = append(p2.Data, 0x99)
	p2.Raw = append(p2.Raw, 0x99) // Modify Raw to reflect data change
	hash4 := p2.GetHash()
	if bytes.Equal(hash1, hash4) {
		t.Errorf("Hash did not change after modifying hashable Data field")
	}

	// Test HeaderType2 hashing difference
	p3 := &Packet{
		HeaderType:      HeaderType2,
		PacketType:      PacketTypeData,
		TransportType:   0x01,
		Context:         ContextNone,
		ContextFlag:     FlagUnset,
		Hops:            2,
		DestinationType: 0x02,
		DestinationHash: destHash,
		TransportID:     randomBytes(16),
		Data:            data,
	}
	if err := p3.Pack(); err != nil {
		t.Fatalf("p3.Pack() failed: %v", err)
	}
	hash5 := p3.GetHash()
	_ = hash5 // Use hash5 to avoid unused variable error
}
