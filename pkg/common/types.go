package common

import (
	"time"
)

// Transport related types
type TransportMode byte
type PathStatus byte

// Path represents routing information for a destination
type Path struct {
	Interface   NetworkInterface
	LastSeen    time.Time
	NextHop     []byte
	Hops        uint8
	LastUpdated time.Time
}

// Common callbacks
type ProofRequestedCallback func([]byte, []byte)
type LinkEstablishedCallback func(interface{})
type PacketCallback func([]byte, NetworkInterface)

// RequestHandler manages path requests and responses
type RequestHandler struct {
	Path              string
	ResponseGenerator func(path string, data []byte, requestID []byte, linkID []byte, remoteIdentity interface{}, requestedAt int64) []byte
	AllowMode         byte
	AllowedList       [][]byte
}

// Interface types
type InterfaceMode byte
type InterfaceType byte

// RatchetIDReceiver holds ratchet ID information
type RatchetIDReceiver struct {
	LatestRatchetID []byte
}

// NetworkStats holds interface statistics
type NetworkStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	LastUpdated     time.Time
}

// LinkStatus represents the current state of a link
type LinkStatus struct {
	Established bool
	LastSeen    time.Time
	RTT         time.Duration
	Quality     float64
	Hops        uint8
}

// PathRequest represents a path discovery request
type PathRequest struct {
	DestinationHash []byte
	Tag             []byte
	TTL             int
	Recursive       bool
}

// PathResponse represents a path discovery response
type PathResponse struct {
	DestinationHash []byte
	NextHop         []byte
	Hops            uint8
	Tag             []byte
}
