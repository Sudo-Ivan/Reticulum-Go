//go:build linux
// +build linux

package interfaces

import (
	"syscall"
	"time"
	"unsafe"
)

func platformGetRTT(fd uintptr) time.Duration {
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
