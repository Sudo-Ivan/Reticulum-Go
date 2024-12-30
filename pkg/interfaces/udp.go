package interfaces

import (
	"fmt"
	"log"
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
	txBytes    uint64
	rxBytes    uint64
	mtu        int
	bitrate    int
	enabled    bool
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
		addr:         udpAddr,
		targetAddr:   targetAddr,
		readBuffer:   make([]byte, common.DEFAULT_MTU),
		mtu:         common.DEFAULT_MTU,
		enabled:     enabled,
	}

	return ui, nil
}

func (ui *UDPInterface) GetName() string {
	return ui.name
}

func (ui *UDPInterface) GetType() common.InterfaceType {
	return ui.ifType
}

func (ui *UDPInterface) GetMode() common.InterfaceMode {
	return ui.mode
}

func (ui *UDPInterface) IsOnline() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.online
}

func (ui *UDPInterface) IsDetached() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.detached
}

func (ui *UDPInterface) Detach() {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.detached = true
	if ui.conn != nil {
		ui.conn.Close()
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
	ui.txBytes += uint64(len(data))
	ui.mutex.Unlock()

	return nil
}

func (ui *UDPInterface) GetConn() net.Conn {
	return ui.conn
}

func (ui *UDPInterface) GetTxBytes() uint64 {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.txBytes
}

func (ui *UDPInterface) GetRxBytes() uint64 {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.rxBytes
}

func (ui *UDPInterface) GetMTU() int {
	return ui.mtu
}

func (ui *UDPInterface) GetBitrate() int {
	return ui.bitrate
}

func (ui *UDPInterface) Enable() {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.online = true
}

func (ui *UDPInterface) Disable() {
	ui.mutex.Lock()
	defer ui.mutex.Unlock()
	ui.online = false
}

func (ui *UDPInterface) Start() error {
	conn, err := net.ListenUDP("udp", ui.addr)
	if err != nil {
		return err
	}
	ui.conn = conn
	ui.online = true
	return nil
}

func (ui *UDPInterface) readLoop() {
	buffer := make([]byte, ui.mtu)
	for {
		if ui.IsDetached() {
			return
		}

		n, addr, err := ui.conn.ReadFromUDP(buffer)
		if err != nil {
			if !ui.IsDetached() {
				log.Printf("UDP read error: %v", err)
			}
			return
		}

		ui.mutex.Lock()
		ui.rxBytes += uint64(n)
		ui.mutex.Unlock()

		log.Printf("Received %d bytes from %s", n, addr.String())

		if callback := ui.GetPacketCallback(); callback != nil {
			callback(buffer[:n], ui)
		}
	}
}

func (ui *UDPInterface) IsEnabled() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.enabled && ui.online && !ui.detached
}
