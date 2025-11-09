package interfaces

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
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
	debug.Log(debug.DEBUG_ALL, "UDP interface sending bytes", "name", ui.Name, "bytes", len(data))

	if !ui.IsEnabled() {
		return fmt.Errorf("interface not enabled")
	}

	if ui.targetAddr == nil {
		return fmt.Errorf("no target address configured")
	}

	// Update TX stats before sending
	ui.mutex.Lock()
	ui.TxBytes += uint64(len(data))
	ui.mutex.Unlock()

	_, err := ui.conn.WriteTo(data, ui.targetAddr)
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "UDP interface write failed", "name", ui.Name, "error", err)
	} else {
		debug.Log(debug.DEBUG_ALL, "UDP interface sent bytes successfully", "name", ui.Name, "bytes", len(data))
	}
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
	
	// Start the read loop in a goroutine
	go ui.readLoop()
	
	return nil
}

func (ui *UDPInterface) readLoop() {
	buffer := make([]byte, common.DEFAULT_MTU)
	for ui.IsOnline() && !ui.IsDetached() {
		n, remoteAddr, err := ui.conn.ReadFromUDP(buffer)
		if err != nil {
			if ui.IsOnline() {
				debug.Log(debug.DEBUG_ERROR, "Error reading from UDP interface", "name", ui.Name, "error", err)
			}
			return
		}

		ui.mutex.Lock()
		if ui.targetAddr == nil {
			debug.Log(debug.DEBUG_ALL, "UDP interface discovered peer", "name", ui.Name, "peer", remoteAddr.String())
			ui.targetAddr = remoteAddr
		}
		ui.mutex.Unlock()

		if ui.packetCallback != nil {
			ui.packetCallback(buffer[:n], ui)
		}
	}
}

func (ui *UDPInterface) IsEnabled() bool {
	ui.mutex.RLock()
	defer ui.mutex.RUnlock()
	return ui.Enabled && ui.Online && !ui.Detached
}
