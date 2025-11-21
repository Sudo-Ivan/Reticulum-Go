// +build openbsd

package interfaces

import (
	"fmt"
	"net"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
)

func (tc *TCPClientInterface) setTimeoutsLinux() error {
	tcpConn, ok := tc.conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	if err := tcpConn.SetKeepAlive(true); err != nil {
		return fmt.Errorf("failed to enable keepalive: %v", err)
	}

	keepalivePeriod := TCP_PROBE_INTERVAL_SEC * time.Second
	if tc.i2pTunneled {
		keepalivePeriod = I2P_PROBE_INTERVAL_SEC * time.Second
	}
	
	if err := tcpConn.SetKeepAlivePeriod(keepalivePeriod); err != nil {
		debug.Log(debug.DEBUG_VERBOSE, "Failed to set keepalive period", "error", err)
	}

	debug.Log(debug.DEBUG_VERBOSE, "TCP keepalive configured (OpenBSD)", "i2p", tc.i2pTunneled)
	return nil
}

func (tc *TCPClientInterface) setTimeoutsOSX() error {
	return tc.setTimeoutsLinux()
}

