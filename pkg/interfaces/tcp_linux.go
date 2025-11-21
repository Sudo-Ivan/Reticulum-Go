// +build linux

package interfaces

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
)

func (tc *TCPClientInterface) setTimeoutsLinux() error {
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
		var userTimeout, probeAfter, probeInterval, probeCount int
		
		if tc.i2pTunneled {
			userTimeout = I2P_USER_TIMEOUT_SEC * 1000
			probeAfter = I2P_PROBE_AFTER_SEC
			probeInterval = I2P_PROBE_INTERVAL_SEC
			probeCount = I2P_PROBES_COUNT
		} else {
			userTimeout = TCP_USER_TIMEOUT_SEC * 1000
			probeAfter = TCP_PROBE_AFTER_SEC
			probeInterval = TCP_PROBE_INTERVAL_SEC
			probeCount = TCP_PROBES_COUNT
		}

		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 18, userTimeout); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to set TCP_USER_TIMEOUT", "error", err)
		}
		
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			sockoptErr = fmt.Errorf("failed to enable SO_KEEPALIVE: %v", err)
			return
		}
		
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 4, probeAfter); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to set TCP_KEEPIDLE", "error", err)
		}
		
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 5, probeInterval); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to set TCP_KEEPINTVL", "error", err)
		}
		
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 6, probeCount); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to set TCP_KEEPCNT", "error", err)
		}
	})

	if err != nil {
		return fmt.Errorf("control failed: %v", err)
	}
	if sockoptErr != nil {
		return sockoptErr
	}

	debug.Log(debug.DEBUG_VERBOSE, "TCP keepalive configured (Linux)", "i2p", tc.i2pTunneled)
	return nil
}

func (tc *TCPClientInterface) setTimeoutsOSX() error {
	return tc.setTimeoutsLinux()
}

func platformGetRTT(fd uintptr) time.Duration {
	var info syscall.TCPInfo
	infoLen := uint32(unsafe.Sizeof(info))
	
	// TCP_INFO is 11 on Linux
	// #nosec G103
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		syscall.IPPROTO_TCP,
		11, // TCP_INFO
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&infoLen)),
		0,
	)
	
	if errno != 0 {
		return 0
	}
	
	return time.Duration(info.Rtt) * time.Microsecond
}
