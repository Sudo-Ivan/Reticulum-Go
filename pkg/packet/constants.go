package packet

const (
	// MTU constants
	EncryptedMDU = 383 // Maximum size of payload data in encrypted packet
	PlainMDU    = 464 // Maximum size of payload data in unencrypted packet

	// Header Types
	HeaderType1 = 0 // Two byte header, one 16 byte address field  
	HeaderType2 = 1 // Two byte header, two 16 byte address fields

	// Propagation Types
	PropagationBroadcast = 0
	PropagationTransport = 1

	// Destination Types
	DestinationSingle = 0
	DestinationGroup  = 1
	DestinationPlain  = 2
	DestinationLink   = 3

	// Packet Types
	PacketData        = 0
	PacketAnnounce    = 1
	PacketLinkRequest = 2
	PacketProof       = 3
) 