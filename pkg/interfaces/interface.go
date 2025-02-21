package interfaces

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	BITRATE_MINIMUM = 1200 // Minimum bitrate in bits/second
	MODE_FULL       = 0x01

	// Interface modes
	MODE_GATEWAY      = 0x02
	MODE_ACCESS_POINT = 0x03
	MODE_ROAMING      = 0x04
	MODE_BOUNDARY     = 0x05

	// Interface types
	TYPE_UDP = 0x01
	TYPE_TCP = 0x02

	PROPAGATION_RATE = 0.02 // 2% of interface bandwidth

	DEBUG_LEVEL = slog.LevelDebug // Default debug level for interface logging

	// Debug levels
	DEBUG_CRITICAL = 1
	DEBUG_ERROR    = 2
	DEBUG_INFO     = 3
	DEBUG_VERBOSE  = 4
	DEBUG_TRACE    = 5
	DEBUG_PACKETS  = 6
	DEBUG_ALL      = 7
)

type Interface interface {
	GetName() string
	GetType() common.InterfaceType
	GetMode() common.InterfaceMode
	IsOnline() bool
	IsDetached() bool
	IsEnabled() bool
	Detach()
	Enable()
	Disable()
	Send(data []byte, addr string) error
	SetPacketCallback(common.PacketCallback)
	GetPacketCallback() common.PacketCallback
	ProcessIncoming([]byte)
	ProcessOutgoing([]byte) error
	SendPathRequest([]byte) error
	SendLinkPacket([]byte, []byte, time.Time) error
	Start() error
	Stop() error
	GetMTU() int
	GetConn() net.Conn
	GetBandwidthAvailable() bool
	common.NetworkInterface
}

type BaseInterface struct {
	Name     string
	Mode     common.InterfaceMode
	Type     common.InterfaceType
	Online   bool
	Enabled  bool
	Detached bool
	IN       bool
	OUT      bool
	MTU      int
	Bitrate  int64
	TxBytes  uint64
	RxBytes  uint64
	lastTx   time.Time

	mutex          sync.RWMutex
	packetCallback common.PacketCallback
}

func NewBaseInterface(name string, ifType common.InterfaceType, enabled bool) BaseInterface {
	return BaseInterface{
		Name:     name,
		Mode:     common.IF_MODE_FULL,
		Type:     ifType,
		Online:   false,
		Enabled:  enabled,
		Detached: false,
		IN:       false,
		OUT:      false,
		MTU:      common.DEFAULT_MTU,
		Bitrate:  BITRATE_MINIMUM,
		lastTx:   time.Now(),
	}
}

func (i *BaseInterface) SetPacketCallback(callback common.PacketCallback) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.packetCallback = callback
}

func (i *BaseInterface) GetPacketCallback() common.PacketCallback {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.packetCallback
}

func (i *BaseInterface) ProcessIncoming(data []byte) {
	i.mutex.Lock()
	i.RxBytes += uint64(len(data))
	i.mutex.Unlock()

	i.mutex.RLock()
	callback := i.packetCallback
	i.mutex.RUnlock()

	if callback != nil {
		callback(data, i)
	}
}

func (i *BaseInterface) ProcessOutgoing(data []byte) error {
	if !i.Online || i.Detached {
		slog.Error("Cannot process outgoing packet - interface offline or detached", "iface", i.Name)
		return fmt.Errorf("interface offline or detached")
	}

	i.mutex.Lock()
	i.TxBytes += uint64(len(data))
	i.mutex.Unlock()

	slog.Log(context.Background(), DEBUG_LEVEL,
		"Processed outgoing packet", "size", len(data),
		"total tx", i.TxBytes, "iface", i.Name)
	return nil
}

func (i *BaseInterface) SendPathRequest(packet []byte) error {
	if !i.Online || i.Detached {
		return fmt.Errorf("interface offline or detached")
	}

	frame := make([]byte, 0, len(packet)+1)
	frame = append(frame, 0x01)
	frame = append(frame, packet...)

	return i.ProcessOutgoing(frame)
}

func (i *BaseInterface) SendLinkPacket(dest []byte, data []byte, timestamp time.Time) error {
	if !i.Online || i.Detached {
		return fmt.Errorf("interface offline or detached")
	}

	frame := make([]byte, 0, len(dest)+len(data)+9)
	frame = append(frame, 0x02)
	frame = append(frame, dest...)

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp.Unix()))
	frame = append(frame, ts...)
	frame = append(frame, data...)

	return i.ProcessOutgoing(frame)
}

func (i *BaseInterface) Detach() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.Detached = true
	i.Online = false
}

func (i *BaseInterface) IsEnabled() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.Enabled && i.Online && !i.Detached
}

func (i *BaseInterface) Enable() {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	prevState := i.Enabled
	i.Enabled = true
	i.Online = true

	slog.Log(context.Background(), DEBUG_LEVEL,
		"State changed ", "iface", i.Name,
		"prevstate", prevState, "state", i.Enabled,
		"online", i.Online)
}

func (i *BaseInterface) Disable() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.Enabled = false
	i.Online = false
	slog.Debug("Interface disabled and offline", "iface", i.Name)
}

func (i *BaseInterface) GetName() string {
	return i.Name
}

func (i *BaseInterface) GetType() common.InterfaceType {
	return i.Type
}

func (i *BaseInterface) GetMode() common.InterfaceMode {
	return i.Mode
}

func (i *BaseInterface) GetMTU() int {
	return i.MTU
}

func (i *BaseInterface) IsOnline() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.Online
}

func (i *BaseInterface) IsDetached() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.Detached
}

func (i *BaseInterface) Start() error {
	return nil
}

func (i *BaseInterface) Stop() error {
	return nil
}

func (i *BaseInterface) Send(data []byte, address string) error {

	slog.Log(context.Background(), DEBUG_LEVEL,
		"Sending data", "size", len(data),
		"destination", address, "iface", i.Name)

	err := i.ProcessOutgoing(data)
	if err != nil {
		slog.Error("Failed to send data", "iface", i.Name, "err", err)
		return err
	}

	i.updateBandwidthStats(uint64(len(data)))
	return nil
}

func (i *BaseInterface) GetConn() net.Conn {
	return nil
}

func (i *BaseInterface) GetBandwidthAvailable() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	now := time.Now()
	timeSinceLastTx := now.Sub(i.lastTx)

	if timeSinceLastTx > time.Second {
		slog.Log(context.Background(), DEBUG_LEVEL, "Bandwidth available",
			"idletime", timeSinceLastTx.Seconds(),
			"iface", i.Name)
		return true
	}

	bytesPerSec := float64(i.TxBytes) / timeSinceLastTx.Seconds()
	currentUsage := bytesPerSec * 8
	maxUsage := float64(i.Bitrate) * PROPAGATION_RATE

	available := currentUsage < maxUsage
	slog.Log(context.Background(), DEBUG_LEVEL, "Bandwidth stats",
		"iface", i.Name,
		"current", fmt.Sprintf("%.2f bps", currentUsage),
		"max", fmt.Sprintf("%.2f bps", maxUsage),
		"usage", fmt.Sprintf("%.1f%%", (currentUsage/maxUsage)*100),
		"available", available)

	return available
}

func (i *BaseInterface) updateBandwidthStats(bytes uint64) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	i.TxBytes += bytes
	i.lastTx = time.Now()

	slog.Log(context.Background(), DEBUG_LEVEL, "Updated bandwidth stats ",
		"iface", i.Name,
		"tx bytes", i.TxBytes,
		"last tx", i.lastTx)

}

type InterceptedInterface struct {
	Interface
	interceptor  func([]byte, common.NetworkInterface) error
	originalSend func([]byte, string) error
}

// Create constructor for intercepted interface
func NewInterceptedInterface(base Interface, interceptor func([]byte, common.NetworkInterface) error) *InterceptedInterface {
	return &InterceptedInterface{
		Interface:    base,
		interceptor:  interceptor,
		originalSend: base.Send,
	}
}

// Implement Send method for intercepted interface
func (i *InterceptedInterface) Send(data []byte, addr string) error {
	// Call interceptor if provided
	if i.interceptor != nil && len(data) > 0 {
		if err := i.interceptor(data, i); err != nil {
			slog.Warn("Failed to intercept outgoing packet", "err", err)
		}
	}

	// Call original send
	return i.originalSend(data, addr)
}
