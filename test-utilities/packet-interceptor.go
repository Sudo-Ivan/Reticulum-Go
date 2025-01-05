package testutils

import (
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

type PacketInterceptor struct {
	mutex       sync.Mutex
	outputFile  *os.File
	isEnabled   bool
	packetCount uint64
}

func NewPacketInterceptor(outputPath string) (*PacketInterceptor, error) {
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %v", err)
	}

	pi := &PacketInterceptor{
		outputFile: file,
		isEnabled:  true,
	}

	// Write header
	header := fmt.Sprintf("=== Packet Capture Started at %s ===\n\n",
		time.Now().UTC().Format("2006-01-02 15:04:05"))
	if _, err := file.WriteString(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write header: %v", err)
	}

	return pi, nil
}

func (pi *PacketInterceptor) Close() error {
	pi.mutex.Lock()
	defer pi.mutex.Unlock()

	if pi.outputFile != nil {
		return pi.outputFile.Close()
	}
	return nil
}

func (pi *PacketInterceptor) InterceptPacket(data []byte, iface common.NetworkInterface, direction string) error {
	pi.mutex.Lock()
	defer pi.mutex.Unlock()

	if !pi.isEnabled || pi.outputFile == nil {
		return nil
	}

	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	pi.packetCount++

	// Format packet info
	logEntry := fmt.Sprintf("[%s] %s packet #%d on interface %s\n",
		timestamp,
		direction,
		pi.packetCount,
		iface.GetName(),
	)

	// Add hex dump of packet data
	logEntry += fmt.Sprintf("Data (%d bytes):\n%s\n\n",
		len(data),
		hex.Dump(data),
	)

	// Write to file
	if _, err := pi.outputFile.WriteString(logEntry); err != nil {
		return fmt.Errorf("failed to write to log file: %v", err)
	}

	// Ensure data is written to disk
	return pi.outputFile.Sync()
}

func (pi *PacketInterceptor) InterceptOutgoing(data []byte, iface common.NetworkInterface) error {
	return pi.InterceptPacket(data, iface, "OUTGOING")
}

func (pi *PacketInterceptor) InterceptIncoming(data []byte, iface common.NetworkInterface) error {
	return pi.InterceptPacket(data, iface, "INCOMING")
}

func (pi *PacketInterceptor) Enable() {
	pi.mutex.Lock()
	defer pi.mutex.Unlock()
	pi.isEnabled = true
}

func (pi *PacketInterceptor) Disable() {
	pi.mutex.Lock()
	defer pi.mutex.Unlock()
	pi.isEnabled = false
}
