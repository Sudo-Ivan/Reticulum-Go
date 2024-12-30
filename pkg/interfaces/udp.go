package interfaces

import (
	"fmt"
	"net"
	"sync"
)

type UDPInterface struct {
	Interface
	conn *net.UDPConn
	listenAddr *net.UDPAddr
	targetAddr *net.UDPAddr
	readBuffer []byte
}

func NewUDPInterface(name string, listenAddr string, targetAddr string) (*UDPInterface, error) {
	ui := &UDPInterface{
		Interface: Interface{
			Name: name,
			Mode: MODE_FULL,
			MTU: 1500,
			Bitrate: 100000000, // 100Mbps estimate for UDP
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
		ui.OUT = true
	}

	// Create UDP connection
	conn, err := net.ListenUDP("udp", ui.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %v", err)
	}
	ui.conn = conn
	ui.IN = true
	ui.Online = true

	// Start read loop
	go ui.readLoop()

	return ui, nil
}

func (ui *UDPInterface) readLoop() {
	for {
		if !ui.Online {
			return
		}

		n, addr, err := ui.conn.ReadFromUDP(ui.readBuffer)
		if err != nil {
			if !ui.Detached {
				// Log error
			}
			continue
		}

		// Copy received data
		data := make([]byte, n)
		copy(data, ui.readBuffer[:n])

		// Process packet
		ui.ProcessIncoming(data)
	}
}

func (ui *UDPInterface) ProcessOutgoing(data []byte) error {
	if !ui.Online || ui.targetAddr == nil {
		return fmt.Errorf("interface offline or no target address configured")
	}

	_, err := ui.conn.WriteToUDP(data, ui.targetAddr)
	if err != nil {
		return fmt.Errorf("UDP write failed: %v", err)
	}

	ui.Interface.ProcessOutgoing(data)
	return nil
}

func (ui *UDPInterface) Detach() {
	ui.Interface.Detach()
	if ui.conn != nil {
		ui.conn.Close()
	}
} 