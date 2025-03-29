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

	// Minimum packet sizes
	MinAnnounceSize = 170 // header(2) + desthash(16) + context(1) + enckey(32) + signkey(32) +
	// namehash(10) + randomhash(10) + signature(64) + min appdata(3)
)
