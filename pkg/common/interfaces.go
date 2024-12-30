package common

import (
    "net"
    "sync"
    "time"
)

// NetworkInterface combines both low-level and high-level interface requirements
type NetworkInterface interface {
    // Low-level network operations
    Start() error
    Stop() error
    Send(data []byte, address string) error
    Receive() ([]byte, string, error)
    GetType() InterfaceType
    GetMode() InterfaceMode
    GetMTU() int
    
    // High-level packet operations
    ProcessIncoming([]byte)
    ProcessOutgoing([]byte) error
    SendPathRequest([]byte) error
    SendLinkPacket([]byte, []byte, time.Time) error
    Detach()
    SetPacketCallback(PacketCallback)
    
    // Additional required fields
    GetName() string
    GetConn() net.Conn
    IsEnabled() bool
}

type PacketCallback func([]byte, interface{})

// BaseInterface provides common implementation
type BaseInterface struct {
    Name     string
    Mode     InterfaceMode
    Type     InterfaceType
    
    Online   bool
    Detached bool
    
    IN       bool
    OUT      bool
    
    MTU      int
    Bitrate  int64
    
    TxBytes  uint64
    RxBytes  uint64
    
    mutex    sync.RWMutex
    owner    interface{}
    packetCallback PacketCallback
} 