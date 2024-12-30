package interfaces

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	HDLC_FLAG     = 0x7E
	HDLC_ESC      = 0x7D
	HDLC_ESC_MASK = 0x20

	KISS_FEND  = 0xC0
	KISS_FESC  = 0xDB
	KISS_TFEND = 0xDC
	KISS_TFESC = 0xDD

	TCP_USER_TIMEOUT    = 24
	TCP_PROBE_AFTER     = 5
	TCP_PROBE_INTERVAL  = 2
	TCP_PROBES         = 12
	RECONNECT_WAIT     = 5
	INITIAL_TIMEOUT    = 5
)

type TCPClientInterface struct {
	Interface
	conn          net.Conn
	targetAddr    string
	targetPort    int
	kissFraming   bool
	i2pTunneled   bool
	initiator     bool
	reconnecting  bool
	neverConnected bool
	writing       bool
	maxReconnectTries int
	packetBuffer []byte
	packetType   byte
}

func NewTCPClient(name string, targetAddr string, targetPort int, kissFraming bool, i2pTunneled bool) (*TCPClientInterface, error) {
	tc := &TCPClientInterface{
		Interface: Interface{
			Name: name,
			Mode: MODE_FULL,
			MTU:  1064,
			Bitrate: 10000000, // 10Mbps estimate
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
		tc.Interface.ProcessIncoming(payload)
	case 0x02: // Link packet
		if len(payload) < 40 { // minimum size for link packet
			return
		}
		tc.Interface.ProcessIncoming(payload)
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

	tc.Interface.ProcessOutgoing(data)
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

type TCPServerInterface struct {
	Interface
	server            net.Listener
	bindAddr          string
	bindPort          int
	i2pTunneled      bool
	preferIPv6       bool
	spawned          []*TCPClientInterface
	spawnedMutex     sync.RWMutex
}

func NewTCPServer(name string, bindAddr string, bindPort int, i2pTunneled bool, preferIPv6 bool) (*TCPServerInterface, error) {
	ts := &TCPServerInterface{
		Interface: Interface{
			Name: name,
			Mode: MODE_FULL,
			MTU:  1064,
			Bitrate: 10000000, // 10Mbps estimate
		},
		bindAddr:    bindAddr,
		bindPort:    bindPort,
		i2pTunneled: i2pTunneled,
		preferIPv6:  preferIPv6,
		spawned:     make([]*TCPClientInterface, 0),
	}

	// Resolve bind address
	var addr string
	if ts.bindAddr == "" {
		if ts.preferIPv6 {
			addr = fmt.Sprintf("[::0]:%d", ts.bindPort)
		} else {
			addr = fmt.Sprintf("0.0.0.0:%d", ts.bindPort)
		}
	} else {
		addr = fmt.Sprintf("%s:%d", ts.bindAddr, ts.bindPort)
	}

	// Create listener
	var err error
	ts.server, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP listener: %v", err)
	}

	ts.Online = true
	ts.IN = true

	// Start accept loop
	go ts.acceptLoop()

	return ts, nil
}

func (ts *TCPServerInterface) acceptLoop() {
	for {
		conn, err := ts.server.Accept()
		if err != nil {
			if !ts.Detached {
				// Log error and continue accepting
				continue
			}
			return
		}

		// Create new client interface for this connection
		client := &TCPClientInterface{
			Interface: Interface{
				Name: fmt.Sprintf("Client-%s-%s", ts.Name, conn.RemoteAddr()),
				Mode: ts.Mode,
				MTU:  ts.MTU,
			},
			conn:        conn,
			i2pTunneled: ts.i2pTunneled,
		}

		// Configure TCP options
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(time.Duration(TCP_PROBE_INTERVAL) * time.Second)
		}

		client.Online = true
		client.IN = ts.IN
		client.OUT = ts.OUT

		// Add to spawned interfaces
		ts.spawnedMutex.Lock()
		ts.spawned = append(ts.spawned, client)
		ts.spawnedMutex.Unlock()

		// Start client read loop
		go client.readLoop()
	}
}

func (ts *TCPServerInterface) Detach() {
	ts.Interface.Detach()
	
	if ts.server != nil {
		ts.server.Close()
	}

	ts.spawnedMutex.Lock()
	for _, client := range ts.spawned {
		client.Detach()
	}
	ts.spawned = nil
	ts.spawnedMutex.Unlock()
}

func (ts *TCPServerInterface) ProcessOutgoing(data []byte) error {
	ts.spawnedMutex.RLock()
	defer ts.spawnedMutex.RUnlock()

	var lastErr error
	for _, client := range ts.spawned {
		if err := client.ProcessOutgoing(data); err != nil {
			lastErr = err
		}
	}

	return lastErr
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