package interfaces

import (
	"fmt"
	"net"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
)

func (tc *TCPClientInterface) setTimeoutsLinux() error {
	return tc.setTimeoutsWindows()
}

func (tc *TCPClientInterface) setTimeoutsOSX() error {
	return tc.setTimeoutsWindows()
}

func (tc *TCPClientInterface) setTimeoutsWindows() error {
	tcpConn, ok := tc.conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	if err := tcpConn.SetKeepAlive(true); err != nil {
		return fmt.Errorf("failed to enable keepalive: %v", err)
	}

	if err := tcpConn.SetKeepAlivePeriod(TCP_PROBE_INTERVAL); err != nil {
		debug.Log(debug.DEBUG_VERBOSE, "Failed to set keepalive period", "error", err)
	}

	debug.Log(debug.DEBUG_VERBOSE, "TCP keepalive configured (Windows)", "i2p", tc.i2pTunneled)
	return nil
}

func platformGetRTT(fd uintptr) time.Duration {
	return 0
}

