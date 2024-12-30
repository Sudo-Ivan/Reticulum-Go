package interfaces

import (
	"fmt"
	"net"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

type UDPInterface struct {
	BaseInterface
	conn *net.UDPConn
	listenAddr *net.UDPAddr
	targetAddr *net.UDPAddr
	readBuffer []byte
}

func NewUDPInterface(name string, listenAddr string, targetAddr string) (*UDPInterface, error) {
	ui := &UDPInterface{
		BaseInterface: BaseInterface{
			BaseInterface: common.BaseInterface{
				Name:    name,
				Mode:    common.IF_MODE_FULL,
				Type:    common.IF_TYPE_UDP,
				MTU:     1500,
				Bitrate: 100000000, // 100Mbps estimate
			},
		},
		readBuffer: make([]byte, 65535),
	}

	// Parse listen address
	laddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address: %v", err)
	}
	ui.listenAddr = laddr

	// Parse target address if provided
	if targetAddr != "" {
		taddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid target address: %v", err)
		}
		ui.targetAddr = taddr
		ui.BaseInterface.OUT = true
	}

	// Create UDP connection
	conn, err := net.ListenUDP("udp", ui.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %v", err)
	}
	ui.conn = conn
	ui.BaseInterface.IN = true
	ui.BaseInterface.Online = true

	// Start read loop
	go ui.readLoop()

	return ui, nil
}

func (ui *UDPInterface) readLoop() {
	for {
		if !ui.BaseInterface.Online {
			return
		}

		n, remoteAddr, err := ui.conn.ReadFromUDP(ui.readBuffer)
		if err != nil {
			if !ui.BaseInterface.Detached {
				continue
			}
			return
		}

		// If no target address is set, use the first sender's address
		if ui.targetAddr == nil {
			ui.targetAddr = remoteAddr
			ui.BaseInterface.OUT = true
		}

		// Copy received data
		data := make([]byte, n)
		copy(data, ui.readBuffer[:n])

		// Process packet
		ui.ProcessIncoming(data)
	}
}

func (ui *UDPInterface) ProcessOutgoing(data []byte) error {
	if !ui.BaseInterface.Online || ui.targetAddr == nil {
		return fmt.Errorf("interface offline or no target address configured")
	}

	_, err := ui.conn.WriteToUDP(data, ui.targetAddr)
	if err != nil {
		return fmt.Errorf("UDP write failed: %v", err)
	}

	ui.BaseInterface.ProcessOutgoing(data)
	return nil
}

func (ui *UDPInterface) Detach() {
	ui.BaseInterface.Detach()
	if ui.conn != nil {
		ui.conn.Close()
	}
}

func (ui *UDPInterface) GetConn() net.Conn {
	return ui.conn
} 