package common

const (
    // Interface Types
    IF_TYPE_UDP InterfaceType = iota
    IF_TYPE_TCP
    IF_TYPE_UNIX

    // Interface Modes
    IF_MODE_FULL InterfaceMode = iota
    IF_MODE_POINT
    IF_MODE_GATEWAY

    // Transport Modes
    TRANSPORT_MODE_DIRECT TransportMode = iota
    TRANSPORT_MODE_RELAY
    TRANSPORT_MODE_GATEWAY

    // Path Status
    PATH_STATUS_UNKNOWN PathStatus = iota
    PATH_STATUS_DIRECT
    PATH_STATUS_RELAY
    PATH_STATUS_FAILED

    // Common Constants
    DEFAULT_MTU = 1500
    MAX_PACKET_SIZE = 65535
) 