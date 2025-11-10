//go:build !linux || tinygo
// +build !linux tinygo

package interfaces

import (
	"time"
)

// platformGetRTT is defined in OS-specific files
// Default implementation for non-Linux platforms
func platformGetRTT(fd uintptr) time.Duration {
	return 0
}
