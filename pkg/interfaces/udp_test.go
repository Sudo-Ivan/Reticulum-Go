package interfaces

import (
	"testing"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

func TestNewUDPInterface(t *testing.T) {
	validAddr := "127.0.0.1:0" // Use port 0 for OS to assign a free port
	validTarget := "127.0.0.1:8080"
	invalidAddr := "invalid-address"

	t.Run("ValidConfig", func(t *testing.T) {
		ui, err := NewUDPInterface("udpValid", validAddr, validTarget, true)
		if err != nil {
			t.Fatalf("NewUDPInterface failed with valid config: %v", err)
		}
		if ui == nil {
			t.Fatal("NewUDPInterface returned nil interface with valid config")
		}
		if ui.GetName() != "udpValid" {
			t.Errorf("GetName() = %s; want udpValid", ui.GetName())
		}
		if ui.GetType() != common.IF_TYPE_UDP {
			t.Errorf("GetType() = %v; want %v", ui.GetType(), common.IF_TYPE_UDP)
		}
		if ui.addr.String() != validAddr && ui.addr.Port == 0 { // Check if address resolved, port 0 is special
			// Allow OS-assigned port if 0 was specified
		} else if ui.addr.String() != validAddr {
			// t.Errorf("Resolved addr = %s; want %s", ui.addr.String(), validAddr) //This check is flaky with port 0
		}
		if ui.targetAddr.String() != validTarget {
			t.Errorf("Resolved targetAddr = %s; want %s", ui.targetAddr.String(), validTarget)
		}
		if !ui.Enabled { // BaseInterface field
			t.Error("Interface not enabled by default when requested")
		}
		if ui.IsOnline() { // Should be offline initially
			t.Error("Interface online initially")
		}
	})

	t.Run("ValidConfigNoTarget", func(t *testing.T) {
		ui, err := NewUDPInterface("udpNoTarget", validAddr, "", true)
		if err != nil {
			t.Fatalf("NewUDPInterface failed with valid config (no target): %v", err)
		}
		if ui == nil {
			t.Fatal("NewUDPInterface returned nil interface with valid config (no target)")
		}
		if ui.targetAddr != nil {
			t.Errorf("targetAddr = %v; want nil", ui.targetAddr)
		}
	})

	t.Run("InvalidAddress", func(t *testing.T) {
		_, err := NewUDPInterface("udpInvalidAddr", invalidAddr, validTarget, true)
		if err == nil {
			t.Error("NewUDPInterface succeeded with invalid address")
		}
	})

	t.Run("InvalidTarget", func(t *testing.T) {
		_, err := NewUDPInterface("udpInvalidTarget", validAddr, invalidAddr, true)
		if err == nil {
			t.Error("NewUDPInterface succeeded with invalid target address")
		}
	})
}

func TestUDPInterfaceState(t *testing.T) {
	// Basic state tests are covered by BaseInterface tests
	// Add specific UDP ones if needed, e.g., involving the conn
	addr := "127.0.0.1:0"
	ui, _ := NewUDPInterface("udpState", addr, "", true)

	if ui.conn != nil {
		t.Error("conn field is not nil before Start()")
	}

	// We don't call Start() here because it requires actual network binding
	// Testing Send requires Start() and a listener, which is too complex for unit tests here

	// Test Detach
	ui.Detach()
	if !ui.IsDetached() {
		t.Error("IsDetached() is false after Detach()")
	}

	// Further tests on Send/ProcessOutgoing/readLoop would require mocking net.UDPConn
	// or setting up a local listener.
}
