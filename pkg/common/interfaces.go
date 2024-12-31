package common

import (
	"net"
	"sync"
	"time"
)

// NetworkInterface defines the interface for all network communication methods
type NetworkInterface interface {
	// Core interface operations
	Start() error
	Stop() error
	Enable()
	Disable()
	Detach()
	
	// Network operations
	Send(data []byte, address string) error
	GetConn() net.Conn
	GetMTU() int
	GetName() string
	
	// Interface properties
	GetType() InterfaceType
	GetMode() InterfaceMode
	IsEnabled() bool
	IsOnline() bool
	IsDetached() bool
	
	// Packet handling
	ProcessIncoming([]byte)
	ProcessOutgoing([]byte) error
	SendPathRequest([]byte) error
	SendLinkPacket([]byte, []byte, time.Time) error
	SetPacketCallback(PacketCallback)
	GetPacketCallback() PacketCallback
}

// BaseInterface provides common implementation for network interfaces
type BaseInterface struct {
	Name     string
	Mode     InterfaceMode
	Type     InterfaceType
	Online   bool
	Enabled  bool
	Detached bool

	IN  bool
	OUT bool

	MTU     int
	Bitrate int64

	TxBytes uint64
	RxBytes uint64

	Mutex          sync.RWMutex
	Owner          interface{}
	PacketCallback PacketCallback
}

// NewBaseInterface creates a new BaseInterface instance
func NewBaseInterface(name string, ifaceType InterfaceType, enabled bool) BaseInterface {
	return BaseInterface{
		Name:    name,
		Type:    ifaceType,
		Mode:    IF_MODE_FULL,
		Enabled: enabled,
		MTU:     DEFAULT_MTU,
	}
}

// Default implementations for BaseInterface
func (i *BaseInterface) GetType() InterfaceType {
	return i.Type
}

func (i *BaseInterface) GetMode() InterfaceMode {
	return i.Mode
}

func (i *BaseInterface) GetMTU() int {
	return i.MTU
}

func (i *BaseInterface) GetName() string {
	return i.Name
}

func (i *BaseInterface) IsEnabled() bool {
	i.Mutex.RLock()
	defer i.Mutex.RUnlock()
	return i.Enabled && i.Online && !i.Detached
}

func (i *BaseInterface) IsOnline() bool {
	i.Mutex.RLock()
	defer i.Mutex.RUnlock()
	return i.Online
}

func (i *BaseInterface) IsDetached() bool {
	i.Mutex.RLock()
	defer i.Mutex.RUnlock()
	return i.Detached
}

func (i *BaseInterface) SetPacketCallback(callback PacketCallback) {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	i.PacketCallback = callback
}

func (i *BaseInterface) GetPacketCallback() PacketCallback {
	i.Mutex.RLock()
	defer i.Mutex.RUnlock()
	return i.PacketCallback
}

func (i *BaseInterface) Detach() {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	i.Detached = true
	i.Online = false
}

func (i *BaseInterface) Enable() {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	i.Enabled = true
	i.Online = true
}

func (i *BaseInterface) Disable() {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	i.Enabled = false
	i.Online = false
}
