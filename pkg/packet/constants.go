package packet

const (
	// MTU constants
	EncryptedMDU = 383 // Maximum size of payload data in encrypted packet
	PlainMDU     = 464 // Maximum size of payload data in unencrypted packet

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
