package interfaces

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
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
	TxBytes           uint64
	RxBytes           uint64
	lastTx            time.Time
	lastRx            time.Time
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
		addr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
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

	addr := net.JoinHostPort(tc.targetAddr, fmt.Sprintf("%d", tc.targetPort))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	tc.conn = conn

	// Set platform-specific timeouts
	switch runtime.GOOS {
	case "linux":
		if err := tc.setTimeoutsLinux(); err != nil {
			debug.Log(debug.DEBUG_ERROR, "Failed to set Linux TCP timeouts", "error", err)
		}
	case "darwin":
		if err := tc.setTimeoutsOSX(); err != nil {
			debug.Log(debug.DEBUG_ERROR, "Failed to set OSX TCP timeouts", "error", err)
		}
	}

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

		// Update RX bytes for raw received data
		tc.UpdateStats(uint64(n), true) // #nosec G115

		for i := 0; i < n; i++ {
			b := buffer[i]

			if b == HDLC_FLAG {
				if inFrame && len(dataBuffer) > 0 {
					tc.handlePacket(dataBuffer)
					dataBuffer = dataBuffer[:0]
				}
				inFrame = !inFrame
				continue
			}

			if inFrame {
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

func (tc *TCPClientInterface) handlePacket(data []byte) {
	if len(data) < 1 {
		debug.Log(debug.DEBUG_ALL, "Received invalid packet: empty")
		return
	}

	tc.mutex.Lock()
	tc.RxBytes += uint64(len(data))
	lastRx := time.Now()
	tc.lastRx = lastRx
	tc.mutex.Unlock()

	debug.Log(debug.DEBUG_ALL, "Received packet", "type", fmt.Sprintf("0x%02x", data[0]), "size", len(data))

	// For RNS packets, call the packet callback directly
	if callback := tc.GetPacketCallback(); callback != nil {
		debug.Log(debug.DEBUG_ALL, "Calling packet callback for RNS packet")
		callback(data, tc)
	} else {
		debug.Log(debug.DEBUG_ALL, "No packet callback set for TCP interface")
	}
}

// Send implements the interface Send method for TCP interface
func (tc *TCPClientInterface) Send(data []byte, address string) error {
	debug.Log(debug.DEBUG_ALL, "TCP interface sending bytes", "name", tc.Name, "bytes", len(data))
	
	if !tc.IsEnabled() || !tc.IsOnline() {
		return fmt.Errorf("TCP interface %s is not online", tc.Name)
	}

	// For TCP interface, we need to prepend a packet type byte for announce packets
	// RNS TCP protocol expects: [packet_type][data]
	frame := make([]byte, 0, len(data)+1)
	frame = append(frame, 0x01) // Announce packet type
	frame = append(frame, data...)

	return tc.ProcessOutgoing(frame)
}

func (tc *TCPClientInterface) ProcessOutgoing(data []byte) error {
	if !tc.Online {
		return fmt.Errorf("interface offline")
	}

	tc.writing = true
	defer func() { tc.writing = false }()

	// For TCP connections, use HDLC framing
	var frame []byte
	frame = append([]byte{HDLC_FLAG}, escapeHDLC(data)...)
	frame = append(frame, HDLC_FLAG)

	// Update TX stats before sending
	tc.UpdateStats(uint64(len(frame)), false)

	debug.Log(debug.DEBUG_ALL, "TCP interface writing to network", "name", tc.Name, "bytes", len(frame))
	_, err := tc.conn.Write(frame)
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "TCP interface write failed", "name", tc.Name, "error", err)
	}
	return err
}

func (tc *TCPClientInterface) teardown() {
	tc.Online = false
	tc.IN = false
	tc.OUT = false
	if tc.conn != nil {
		tc.conn.Close() // #nosec G104
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

		addr := net.JoinHostPort(tc.targetAddr, fmt.Sprintf("%d", tc.targetPort))

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

func (tc *TCPClientInterface) GetRTT() time.Duration {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	if !tc.IsConnected() {
		return 0
	}

	if tcpConn, ok := tc.conn.(*net.TCPConn); ok {
		var rtt time.Duration = 0
		if runtime.GOOS == "linux" {
			if info, err := tcpConn.SyscallConn(); err == nil {
				if err := info.Control(func(fd uintptr) { // #nosec G104
					rtt = platformGetRTT(fd)
				}); err != nil {
					debug.Log(debug.DEBUG_ERROR, "Error in SyscallConn Control", "error", err)
				}
			}
		}
		return rtt
	}

	return 0
}

func (tc *TCPClientInterface) GetTxBytes() uint64 {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.TxBytes
}

func (tc *TCPClientInterface) GetRxBytes() uint64 {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.RxBytes
}

func (tc *TCPClientInterface) UpdateStats(bytes uint64, isRx bool) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	now := time.Now()
	if isRx {
		tc.RxBytes += bytes
		tc.lastRx = now
		debug.Log(debug.DEBUG_TRACE, "Interface RX stats", "name", tc.Name, "bytes", bytes, "total", tc.RxBytes, "last", tc.lastRx)
	} else {
		tc.TxBytes += bytes
		tc.lastTx = now
		debug.Log(debug.DEBUG_TRACE, "Interface TX stats", "name", tc.Name, "bytes", bytes, "total", tc.TxBytes, "last", tc.lastTx)
	}
}

func (tc *TCPClientInterface) GetStats() (tx uint64, rx uint64, lastTx time.Time, lastRx time.Time) {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return tc.TxBytes, tc.RxBytes, tc.lastTx, tc.lastRx
}

func (tc *TCPClientInterface) setTimeoutsLinux() error {
	tcpConn, ok := tc.conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	if !tc.i2pTunneled {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return err
		}
		if err := tcpConn.SetKeepAlivePeriod(time.Duration(TCP_PROBE_INTERVAL) * time.Second); err != nil {
			return err
		}
	}

	return nil
}

func (tc *TCPClientInterface) setTimeoutsOSX() error {
	tcpConn, ok := tc.conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}

	return nil
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
	TxBytes        uint64
	RxBytes        uint64
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

	addr := fmt.Sprintf("%s:%d", ts.bindAddr, ts.bindPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start TCP server: %w", err)
	}

	ts.Online = true

	// Accept connections in a goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !ts.Online {
					return // Normal shutdown
				}
				debug.Log(debug.DEBUG_ERROR, "Error accepting connection", "error", err)
				continue
			}

			// Handle each connection in a separate goroutine
			go ts.handleConnection(conn)
		}
	}()

	return nil
}

func (ts *TCPServerInterface) Stop() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.Online = false
	return nil
}

func (ts *TCPServerInterface) GetTxBytes() uint64 {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.TxBytes
}

func (ts *TCPServerInterface) GetRxBytes() uint64 {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	return ts.RxBytes
}

func (ts *TCPServerInterface) handleConnection(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	ts.mutex.Lock()
	ts.connections[addr] = conn
	ts.mutex.Unlock()

	defer func() {
		ts.mutex.Lock()
		delete(ts.connections, addr)
		ts.mutex.Unlock()
		conn.Close() // #nosec G104
	}()

	buffer := make([]byte, ts.MTU)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}

		ts.mutex.Lock()
		ts.RxBytes += uint64(n) // #nosec G115
		ts.mutex.Unlock()

		if ts.packetCallback != nil {
			ts.packetCallback(buffer[:n], ts)
		}
	}
}

func (ts *TCPServerInterface) ProcessOutgoing(data []byte) error {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	if !ts.Online {
		return fmt.Errorf("interface offline")
	}

	var frame []byte
	if ts.kissFraming {
		frame = append([]byte{KISS_FEND}, escapeKISS(data)...)
		frame = append(frame, KISS_FEND)
	} else {
		frame = append([]byte{HDLC_FLAG}, escapeHDLC(data)...)
		frame = append(frame, HDLC_FLAG)
	}

	ts.TxBytes += uint64(len(frame))

	for _, conn := range ts.connections {
		if _, err := conn.Write(frame); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Error writing to connection", "address", conn.RemoteAddr(), "error", err)
		}
	}

	return nil
}
