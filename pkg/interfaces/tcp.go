package interfaces

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

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
	INITIAL_BACKOFF    = time.Second
	MAX_BACKOFF        = time.Minute * 5
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
	mutex             sync.RWMutex
	enabled           bool
}

func NewTCPClientInterface(name string, targetHost string, targetPort int, kissFraming bool, i2pTunneled bool, enabled bool) (*TCPClientInterface, error) {
	tc := &TCPClientInterface{
		BaseInterface:     NewBaseInterface(name, common.IF_TYPE_TCP, enabled),
		targetAddr:        targetHost,
		targetPort:        targetPort,
		kissFraming:       kissFraming,
		i2pTunneled:       i2pTunneled,
		initiator:         true,
		enabled:           enabled,
		maxReconnectTries: TCP_PROBES,
		packetBuffer:      make([]byte, 0),
		neverConnected:    true,
	}

	if enabled {
		addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tc.conn = conn
		tc.Online = true
		go tc.readLoop()
	}

	return tc, nil
}

func (tc *TCPClientInterface) Start() error {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if !tc.Enabled {
		return fmt.Errorf("interface not enabled")
	}

	if tc.conn != nil {
		tc.Online = true
		go tc.readLoop()
		return nil
	}

	addr := fmt.Sprintf("%s:%d", tc.targetAddr, tc.targetPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	tc.conn = conn
	tc.Online = true
	go tc.readLoop()
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

	tc.mutex.Lock()
	tc.packetType = data[0]
	tc.mutex.Unlock()

	payload := data[1:]

	switch tc.packetType {
	case 0x01: // Announce packet
		if len(payload) >= 53 { // Minimum announce size
			tc.BaseInterface.ProcessIncoming(payload)
		}
	case 0x02: // Link packet
		if len(payload) < 40 { // minimum size for link packet
			return
		}
		tc.BaseInterface.ProcessIncoming(payload)
	case 0x03: // Announce packet
		tc.BaseInterface.ProcessIncoming(payload)
	case 0x04: // Transport packet
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
	return tc.enabled && tc.Online && !tc.Detached
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
	return tc.Detached
}

func (tc *TCPClientInterface) IsOnline() bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.Online
}

func (tc *TCPClientInterface) reconnect() {
	tc.mutex.Lock()
	if tc.reconnecting {
		tc.mutex.Unlock()
		return
	}
	tc.reconnecting = true
	tc.mutex.Unlock()

	backoff := time.Second
	maxBackoff := time.Minute * 5
	retries := 0

	for retries < tc.maxReconnectTries {
		tc.teardown()

		addr := fmt.Sprintf("%s:%d", tc.targetAddr, tc.targetPort)

		conn, err := net.Dial("tcp", addr)
		if err == nil {
			tc.mutex.Lock()
			tc.conn = conn
			tc.Online = true

			tc.neverConnected = false
			tc.reconnecting = false
			tc.mutex.Unlock()

			go tc.readLoop()
			return
		}

		// Log reconnection attempt
		fmt.Printf("Failed to reconnect to %s (attempt %d/%d): %v\n",
			addr, retries+1, tc.maxReconnectTries, err)

		// Wait with exponential backoff
		time.Sleep(backoff)

		// Increase backoff time exponentially
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}

		retries++
	}

	tc.mutex.Lock()
	tc.reconnecting = false
	tc.mutex.Unlock()

	// If we've exhausted all retries, perform final teardown
	tc.teardown()
	fmt.Printf("Failed to reconnect to %s after %d attempts\n",
		fmt.Sprintf("%s:%d", tc.targetAddr, tc.targetPort), tc.maxReconnectTries)
}

func (tc *TCPClientInterface) Enable() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.Online = true
}

func (tc *TCPClientInterface) Disable() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.Online = false
}

func (tc *TCPClientInterface) IsConnected() bool {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.conn != nil && tc.Online && !tc.reconnecting
}

func getRTTFromSocket(fd uintptr) time.Duration {
	var info syscall.TCPInfo
	size := uint32(syscall.SizeofTCPInfo)

	_, _, err := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		syscall.SOL_TCP,
		syscall.TCP_INFO,
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if err != 0 {
		return 0
	}

	// RTT is in microseconds, convert to Duration
	return time.Duration(info.Rtt) * time.Microsecond
}

func (tc *TCPClientInterface) GetRTT() time.Duration {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	if !tc.IsConnected() {
		return 0
	}

	if tcpConn, ok := tc.conn.(*net.TCPConn); ok {
		var rtt time.Duration
		if info, err := tcpConn.SyscallConn(); err == nil {
			info.Control(func(fd uintptr) {
				rtt = getRTTFromSocket(fd)
			})
			return rtt
		}
	}

	return 0
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
}

func NewTCPServerInterface(name string, bindAddr string, bindPort int, kissFraming bool, i2pTunneled bool, preferIPv6 bool) (*TCPServerInterface, error) {
	ts := &TCPServerInterface{
		BaseInterface: BaseInterface{
			Name:     name,
			Mode:     common.IF_MODE_FULL,
			Type:     common.IF_TYPE_TCP,
			Online:   false,
			MTU:      common.DEFAULT_MTU,
			Detached: false,
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
	return fmt.Sprintf("TCPServerInterface[%s/%s:%d]", ts.Name, addr, ts.bindPort)
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
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.BaseInterface.Enabled && ts.BaseInterface.Online && !ts.BaseInterface.Detached
}

func (ts *TCPServerInterface) GetName() string {
	return ts.Name
}

func (ts *TCPServerInterface) IsDetached() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.BaseInterface.Detached
}

func (ts *TCPServerInterface) IsOnline() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.Online
}

func (ts *TCPServerInterface) Enable() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.Online = true
}

func (ts *TCPServerInterface) Disable() {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.Online = false
}

func (ts *TCPServerInterface) Start() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.Online = true
	return nil
}

func (ts *TCPServerInterface) Stop() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.Online = false
	return nil
}
