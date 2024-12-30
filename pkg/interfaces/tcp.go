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
}

func NewTCPClient(name string, targetAddr string, targetPort int, kissFraming bool, i2pTunneled bool) (*TCPClientInterface, error) {
	tc := &TCPClientInterface{
		BaseInterface: BaseInterface{
			name:     name,
			mode:     common.IF_MODE_FULL,
			ifType:   common.IF_TYPE_TCP,
			online:   false,
			mtu:      1064,
			detached: false,
		},
		targetAddr:  targetAddr,
		targetPort:  targetPort,
		kissFraming: kissFraming,
		i2pTunneled: i2pTunneled,
		initiator:   true,
	}

	if err := tc.connect(true); err != nil {
		go tc.reconnect()
	} else {
		go tc.readLoop()
	}

	return tc, nil
}

func (tc *TCPClientInterface) connect(initial bool) error {
	addr := fmt.Sprintf("%s:%d", tc.targetAddr, tc.targetPort)
	conn, err := net.DialTimeout("tcp", addr, time.Second*INITIAL_TIMEOUT)
	if err != nil {
		if initial {
			return fmt.Errorf("initial connection failed: %v", err)
		}
		return err
	}

	tc.conn = conn
	tc.Online = true
	tc.writing = false
	tc.neverConnected = false

	// Set TCP options
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(time.Second * TCP_PROBE_INTERVAL)
	}

	return nil
}

func (tc *TCPClientInterface) reconnect() {
	if tc.initiator && !tc.reconnecting {
		tc.reconnecting = true
		attempts := 0

		for !tc.Online {
			time.Sleep(time.Second * RECONNECT_WAIT)
			attempts++

			if tc.maxReconnectTries > 0 && attempts > tc.maxReconnectTries {
				tc.teardown()
				break
			}

			if err := tc.connect(false); err != nil {
				continue
			}

			go tc.readLoop()
			break
		}

		tc.reconnecting = false
	}
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
	return tc.Online
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

type TCPServerInterface struct {
	BaseInterface
	listener       net.Listener
	connections    map[string]net.Conn
	mutex          sync.RWMutex
	bindAddr       string
	bindPort       int
	preferIPv6     bool
	spawned        bool
	port           int
	host           string
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
