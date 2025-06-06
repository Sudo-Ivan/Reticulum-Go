package common

const (
	// Interface Types
	IF_TYPE_NONE InterfaceType = iota
	IF_TYPE_UDP
	IF_TYPE_TCP
	IF_TYPE_UNIX
	IF_TYPE_I2P
	IF_TYPE_BLUETOOTH
	IF_TYPE_SERIAL
	IF_TYPE_AUTO

	// Interface Modes
	IF_MODE_FULL InterfaceMode = iota
	IF_MODE_POINT
	IF_MODE_GATEWAY
	IF_MODE_ACCESS_POINT
	IF_MODE_ROAMING
	IF_MODE_BOUNDARY

	// Transport Modes
	TRANSPORT_MODE_DIRECT TransportMode = iota
	TRANSPORT_MODE_RELAY
	TRANSPORT_MODE_GATEWAY

	// Path Status
	PATH_STATUS_UNKNOWN PathStatus = iota
	PATH_STATUS_DIRECT
	PATH_STATUS_RELAY
	PATH_STATUS_FAILED

	// Resource Status
	RESOURCE_STATUS_PENDING   = 0x00
	RESOURCE_STATUS_ACTIVE    = 0x01
	RESOURCE_STATUS_COMPLETE  = 0x02
	RESOURCE_STATUS_FAILED    = 0x03
	RESOURCE_STATUS_CANCELLED = 0x04

	// Link Status
	LINK_STATUS_PENDING = 0x00
	LINK_STATUS_ACTIVE  = 0x01
	LINK_STATUS_CLOSED  = 0x02
	LINK_STATUS_FAILED  = 0x03

	// Direction Constants
	IN  = 0x01
	OUT = 0x02

	// Common Constants
	DEFAULT_MTU     = 1500
	MAX_PACKET_SIZE = 65535
	BITRATE_MINIMUM = 5

	// Timeouts and Intervals
	ESTABLISH_TIMEOUT  = 6
	KEEPALIVE_INTERVAL = 360
	STALE_TIME         = 720
	PATH_REQUEST_TTL   = 300
	ANNOUNCE_TIMEOUT   = 15
)
