package interfaces

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	HDLC_FLAG     = 0x7E
	HDLC_ESC      = 0x7D
	HDLC_ESC_MASK = 0x20

	KISS_FEND  = 0xC0
	KISS_FESC  = 0xDB
	KISS_TFEND = 0xDC
	KISS_TFESC = 0xDD

	TCP_USER_TIMEOUT   = 24
	TCP_PROBE_AFTER    = 5
	TCP_PROBE_INTERVAL = 2
	TCP_PROBES         = 12
	RECONNECT_WAIT     = 5
	INITIAL_TIMEOUT    = 5
)

type TCPClientInterface struct {
	BaseInterface
	conn              net.Conn
	targetAddr        string
	targetPort        int
	kissFraming       bool
	i2pTunneled       bool
	initiator         bool
	reconnecting      bool
	neverConnected    bool
	writing           bool
	maxReconnectTries int
	packetBuffer      []byte
	packetType        byte
	packetCallback    common.PacketCallback
	mutex             sync.RWMutex
	detached          bool
	enabled           bool
}

func NewTCPClient(name string, targetHost string, targetPort int, kissFraming bool, i2pTunneled bool, enabled bool) (*TCPClientInterface, error) {
	tc := &TCPClientInterface{
		BaseInterface: NewBaseInterface(name, common.IF_TYPE_TCP, enabled),
		targetAddr:    targetHost,
		targetPort:    targetPort,
		kissFraming:   kissFraming,
		i2pTunneled:   i2pTunneled,
		initiator:     true,
		enabled:       enabled,
	}

	if enabled {
		addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tc.conn = conn
		tc.online = true
	}

	return tc, nil
}

func (tc *TCPClientInterface) Start() error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if !tc.enabled {
		return fmt.Errorf("interface not enabled")
	}

	if tc.conn != nil {
		tc.online = true
		return nil
	}

	addr := fmt.Sprintf("%s:%d", tc.targetAddr, tc.targetPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	tc.conn = conn
	tc.online = true
	return nil
}

func (tc *TCPClientInterface) readLoop() {
	buffer := make([]byte, tc.MTU)
	inFrame := false
	escape := false
	dataBuffer := make([]byte, 0)

	for {
		n, err := tc.conn.Read(buffer)
		if err != nil {
			tc.Online = false
			if tc.initiator && !tc.Detached {
				go tc.reconnect()
			} else {
				tc.teardown()
			}
			return
		}

		for i := 0; i < n; i++ {
			b := buffer[i]

			if tc.kissFraming {
				// KISS framing logic
				if inFrame && b == KISS_FEND {
					inFrame = false
					tc.handlePacket(dataBuffer)
					dataBuffer = dataBuffer[:0]
				} else if b == KISS_FEND {
					inFrame = true
				} else if inFrame {
					if b == KISS_FESC {
						escape = true
					} else {
						if escape {
							if b == KISS_TFEND {
								b = KISS_FEND
							}
							if b == KISS_TFESC {
								b = KISS_FESC
							}
							escape = false
						}
						dataBuffer = append(dataBuffer, b)
					}
				}
			} else {
				// HDLC framing logic
				if inFrame && b == HDLC_FLAG {
					inFrame = false
					tc.handlePacket(dataBuffer)
					dataBuffer = dataBuffer[:0]
				} else if b == HDLC_FLAG {
					inFrame = true
				} else if inFrame {
					if b == HDLC_ESC {
						escape = true
					} else {
						if escape {
							b ^= HDLC_ESC_MASK
							escape = false
						}
						dataBuffer = append(dataBuffer, b)
					}
				}
			}
		}
	}
}

func (tc *TCPClientInterface) handlePacket(data []byte) {
	if len(data) < 1 {
		return
	}

	packetType := data[0]
	payload := data[1:]

	switch packetType {
	case 0x01: // Path request
		tc.BaseInterface.ProcessIncoming(payload)
	case 0x02: // Link packet
		if len(payload) < 40 { // minimum size for link packet
			return
		}
		tc.BaseInterface.ProcessIncoming(payload)
	default:
		// Unknown packet type
		return
	}
}

func (tc *TCPClientInterface) ProcessOutgoing(data []byte) error {
	if !tc.Online {
		return fmt.Errorf("interface offline")
	}

	tc.writing = true
	defer func() { tc.writing = false }()

	var frame []byte
	if tc.kissFraming {
		frame = append([]byte{KISS_FEND}, escapeKISS(data)...)
		frame = append(frame, KISS_FEND)
	} else {
		frame = append([]byte{HDLC_FLAG}, escapeHDLC(data)...)
		frame = append(frame, HDLC_FLAG)
	}

	if _, err := tc.conn.Write(frame); err != nil {
		tc.teardown()
		return fmt.Errorf("write failed: %v", err)
	}

	tc.BaseInterface.ProcessOutgoing(data)
	return nil
}

func (tc *TCPClientInterface) teardown() {
	tc.Online = false
	tc.IN = false
	tc.OUT = false
	if tc.conn != nil {
		tc.conn.Close()
	}
}

// Helper functions for escaping data
func escapeHDLC(data []byte) []byte {
	escaped := make([]byte, 0, len(data)*2)
	for _, b := range data {
		if b == HDLC_FLAG || b == HDLC_ESC {
			escaped = append(escaped, HDLC_ESC, b^HDLC_ESC_MASK)
		} else {
			escaped = append(escaped, b)
		}
	}
	return escaped
}

func escapeKISS(data []byte) []byte {
	escaped := make([]byte, 0, len(data)*2)
	for _, b := range data {
		if b == KISS_FEND {
			escaped = append(escaped, KISS_FESC, KISS_TFEND)
		} else if b == KISS_FESC {
			escaped = append(escaped, KISS_FESC, KISS_TFESC)
		} else {
			escaped = append(escaped, b)
		}
	}
	return escaped
}

func (tc *TCPClientInterface) SetPacketCallback(cb common.PacketCallback) {
	tc.packetCallback = cb
}

func (tc *TCPClientInterface) IsEnabled() bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.enabled && tc.online && !tc.detached
}

func (tc *TCPClientInterface) GetName() string {
	return tc.Name
}

func (tc *TCPClientInterface) GetPacketCallback() common.PacketCallback {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.packetCallback
}

func (tc *TCPClientInterface) IsDetached() bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.detached
}

func (tc *TCPClientInterface) IsOnline() bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.online
}

func (tc *TCPClientInterface) reconnect() {
	tc.mutex.Lock()
	if tc.reconnecting {
		tc.mutex.Unlock()
		return
	}
	tc.reconnecting = true
	tc.mutex.Unlock()

	retries := 0
	for retries < tc.maxReconnectTries {
		tc.teardown()

		addr := fmt.Sprintf("%s:%d", tc.targetAddr, tc.targetPort)
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			tc.mutex.Lock()
			tc.conn = conn
			tc.online = true
			tc.neverConnected = false
			tc.reconnecting = false
			tc.mutex.Unlock()

			// Restart read loop
			go tc.readLoop()
			return
		}

		retries++
		// Wait before retrying
		select {
		case <-time.After(RECONNECT_WAIT * time.Second):
			continue
		}
	}

	// Failed to reconnect after max retries
	tc.mutex.Lock()
	tc.reconnecting = false
	tc.mutex.Unlock()
	tc.teardown()
}

func (tc *TCPClientInterface) Enable() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.online = true
}

func (tc *TCPClientInterface) Disable() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.online = false
}

type TCPServerInterface struct {
	BaseInterface
	connections    map[string]net.Conn
	mutex          sync.RWMutex
	bindAddr       string
	bindPort       int
	preferIPv6     bool
	kissFraming    bool
	i2pTunneled    bool
	packetCallback common.PacketCallback
	detached       bool
}

func NewTCPServer(name string, bindAddr string, bindPort int, kissFraming bool, i2pTunneled bool, preferIPv6 bool) (*TCPServerInterface, error) {
	ts := &TCPServerInterface{
		BaseInterface: BaseInterface{
			name:     name,
			mode:     common.IF_MODE_FULL,
			ifType:   common.IF_TYPE_TCP,
			online:   false,
			mtu:      common.DEFAULT_MTU,
			detached: false,
		},
		connections: make(map[string]net.Conn),
		bindAddr:    bindAddr,
		bindPort:    bindPort,
		preferIPv6:  preferIPv6,
		kissFraming: kissFraming,
		i2pTunneled: i2pTunneled,
	}

	return ts, nil
}

func (ts *TCPServerInterface) String() string {
	addr := ts.bindAddr
	if addr == "" {
		if ts.preferIPv6 {
			addr = "[::0]"
		} else {
			addr = "0.0.0.0"
		}
	}
	return fmt.Sprintf("TCPServerInterface[%s/%s:%d]", ts.name, addr, ts.bindPort)
}

func (ts *TCPServerInterface) SetPacketCallback(callback common.PacketCallback) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.packetCallback = callback
}

func (ts *TCPServerInterface) GetPacketCallback() common.PacketCallback {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.packetCallback
}

func (ts *TCPServerInterface) IsEnabled() bool {
	return ts.online
}

func (ts *TCPServerInterface) GetName() string {
	return ts.name
}

func (ts *TCPServerInterface) IsDetached() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.detached
}

func (ts *TCPServerInterface) IsOnline() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.online
}

func (ts *TCPServerInterface) Enable() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.online = true
}

func (ts *TCPServerInterface) Disable() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.online = false
}
