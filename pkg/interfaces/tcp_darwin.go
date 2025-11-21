// +build darwin

package interfaces

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
)

func (tc *TCPClientInterface) setTimeoutsLinux() error {
	return tc.setTimeoutsOSX()
}

func (tc *TCPClientInterface) setTimeoutsOSX() error {
	tcpConn, ok := tc.conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %v", err)
	}

	var sockoptErr error
	err = rawConn.Control(func(fd uintptr) {
		const TCP_KEEPALIVE = 0x10
		
		var probeAfter int
		if tc.i2pTunneled {
			probeAfter = I2P_PROBE_AFTER_SEC
		} else {
			probeAfter = TCP_PROBE_AFTER_SEC
		}
		
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			sockoptErr = fmt.Errorf("failed to enable SO_KEEPALIVE: %v", err)
			return
		}
		
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_KEEPALIVE, probeAfter); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to set TCP_KEEPALIVE", "error", err)
		}
	})

	if err != nil {
		return fmt.Errorf("control failed: %v", err)
	}
	if sockoptErr != nil {
		return sockoptErr
	}

	debug.Log(debug.DEBUG_VERBOSE, "TCP keepalive configured (OSX)", "i2p", tc.i2pTunneled)
	return nil
}

func platformGetRTT(fd uintptr) time.Duration {
	return 0
}

