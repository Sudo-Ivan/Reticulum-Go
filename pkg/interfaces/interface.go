package interfaces

import (
	"fmt"
	"time"
	"encoding/binary"
	"net"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	BITRATE_MINIMUM = 5 // Minimum required bitrate in bits/sec
	MODE_FULL      = 0x01
)

type Interface interface {
	common.NetworkInterface
	Send(data []byte, target string) error
	Detach()
	IsEnabled() bool
	GetName() string
}

type BaseInterface struct {
	common.BaseInterface
}

func (i *BaseInterface) SetPacketCallback(callback common.PacketCallback) {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	i.PacketCallback = callback
}

func (i *BaseInterface) ProcessIncoming(data []byte) {
	i.Mutex.RLock()
	callback := i.PacketCallback
	i.Mutex.RUnlock()
	
	if callback != nil {
		callback(data, i)
	}
	
	i.RxBytes += uint64(len(data))
}

func (i *BaseInterface) ProcessOutgoing(data []byte) error {
	i.TxBytes += uint64(len(data))
	return nil
}

func (i *BaseInterface) Detach() {
	i.Mutex.Lock()
	defer i.Mutex.Unlock()
	i.Detached = true
	i.Online = false
}

func (i *BaseInterface) SendPathRequest(packet []byte) error {
	if !i.Online || i.Detached {
		return fmt.Errorf("interface offline or detached")
	}

	frame := make([]byte, 0, len(packet)+2)
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

func (i *BaseInterface) Start() error {
	return nil
}

func (i *BaseInterface) Stop() error {
	return nil
}

func (i *BaseInterface) Send(data []byte, address string) error {
	return i.ProcessOutgoing(data)
}

func (i *BaseInterface) Receive() ([]byte, string, error) {
	return nil, "", nil
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

func (i *BaseInterface) GetName() string {
	return i.Name
}

func (i *BaseInterface) GetConn() net.Conn {
	return nil
}

func (i *BaseInterface) IsEnabled() bool {
	return i.Online && !i.Detached
} 