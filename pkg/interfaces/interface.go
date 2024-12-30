package interfaces

import (
	"fmt"
	"sync"
	"time"
	"encoding/binary"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	BITRATE_MINIMUM = 5 // Minimum required bitrate in bits/sec
)

// BaseInterface embeds common.BaseInterface and implements common.Interface
type BaseInterface struct {
	common.BaseInterface
}

func (i *BaseInterface) SetPacketCallback(callback common.PacketCallback) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.packetCallback = callback
}

func (i *BaseInterface) ProcessIncoming(data []byte) {
	i.mutex.RLock()
	callback := i.packetCallback
	i.mutex.RUnlock()
	
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
	i.mutex.Lock()
	defer i.mutex.Unlock()
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