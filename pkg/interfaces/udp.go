package interfaces

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

type UDPInterface struct {
	BaseInterface
	conn       *net.UDPConn
	addr       *net.UDPAddr
	targetAddr *net.UDPAddr
	mutex      sync.RWMutex
	readBuffer []byte
}

func NewUDPInterface(name string, addr string, target string, enabled bool) (*UDPInterface, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	var targetAddr *net.UDPAddr
	if target != "" {
		targetAddr, err = net.ResolveUDPAddr("udp", target)
		if err != nil {
			return nil, err
		}
	}

	ui := &UDPInterface{
		BaseInterface: NewBaseInterface(name, common.IF_TYPE_UDP, enabled),
		addr:          udpAddr,
		targetAddr:    targetAddr,
		readBuffer:    make([]byte, common.DEFAULT_MTU),
	}

	return ui, nil
}

func (ui *UDPInterface) GetName() string {
	return ui.Name
}

func (ui *UDPInterface) GetType() common.InterfaceType {
	return ui.Type
}

func (ui *UDPInterface) GetMode() common.InterfaceMode {
	return ui.Mode
}

func (ui *UDPInterface) IsOnline() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.Online
}

func (ui *UDPInterface) IsDetached() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.Detached
}

func (ui *UDPInterface) Detach() {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.Detached = true
	if ui.conn != nil {
		ui.conn.Close() // #nosec G104
	}
}

func (ui *UDPInterface) Send(data []byte, addr string) error {
	if !ui.IsEnabled() {
		return fmt.Errorf("interface not enabled")
	}

	if ui.targetAddr == nil {
		return fmt.Errorf("no target address configured")
	}

	_, err := ui.conn.WriteTo(data, ui.targetAddr)
	return err
}

func (ui *UDPInterface) SetPacketCallback(callback common.PacketCallback) {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.packetCallback = callback
}

func (ui *UDPInterface) GetPacketCallback() common.PacketCallback {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.packetCallback
}

func (ui *UDPInterface) ProcessIncoming(data []byte) {
	if callback := ui.GetPacketCallback(); callback != nil {
		callback(data, ui)
	}
}

func (ui *UDPInterface) ProcessOutgoing(data []byte) error {
	if !ui.IsOnline() {
		return fmt.Errorf("interface offline")
	}

	if ui.targetAddr == nil {
		return fmt.Errorf("no target address configured")
	}

	_, err := ui.conn.WriteToUDP(data, ui.targetAddr)
	if err != nil {
		return fmt.Errorf("UDP write failed: %v", err)
	}

	ui.mutex.Lock()
	ui.TxBytes += uint64(len(data))
	ui.mutex.Unlock()

	return nil
}

func (ui *UDPInterface) GetConn() net.Conn {
	return ui.conn
}

func (ui *UDPInterface) GetTxBytes() uint64 {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.TxBytes
}

func (ui *UDPInterface) GetRxBytes() uint64 {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.RxBytes
}

func (ui *UDPInterface) GetMTU() int {
	return ui.MTU
}

func (ui *UDPInterface) GetBitrate() int {
	return int(ui.Bitrate)
}

func (ui *UDPInterface) Enable() {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.Online = true
}

func (ui *UDPInterface) Disable() {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.Online = false
}

func (ui *UDPInterface) Start() error {
	conn, err := net.ListenUDP("udp", ui.addr)
	if err != nil {
		return err
	}
	ui.conn = conn
	ui.Online = true
	return nil
}

/*
func (ui *UDPInterface) readLoop() {
	buffer := make([]byte, ui.MTU)
	for {
		n, _, err := ui.conn.ReadFromUDP(buffer)
		if err != nil {
			if ui.Online {
				log.Printf("Error reading from UDP interface %s: %v", ui.Name, err)
				ui.Stop() // Consider if stopping is the right action or just log and continue
			}
			return
		}
		if ui.packetCallback != nil {
			ui.packetCallback(buffer[:n], ui)
		}
	}
}
*/

func (ui *UDPInterface) IsEnabled() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.Enabled && ui.Online && !ui.Detached
}
