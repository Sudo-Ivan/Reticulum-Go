package common

import (
	"time"
)

// Transport related types
type TransportMode byte
type PathStatus byte

// Common structs
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

// Request handler
type RequestHandler struct {
	Path              string
	ResponseGenerator func(path string, data []byte, requestID []byte, linkID []byte, remoteIdentity interface{}, requestedAt int64) []byte
	AllowMode         byte
	AllowedList       [][]byte
}
type InterfaceMode byte
type InterfaceType byte

// PacketCallback defines the function signature for packet handling
type PacketCallback func([]byte, interface{})
