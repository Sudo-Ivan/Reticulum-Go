package interfaces

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

func TestBaseInterfaceStateChanges(t *testing.T) {
	bi := NewBaseInterface("test", common.IF_TYPE_TCP, false) // Start disabled

	if bi.IsEnabled() {
		t.Error("Newly created disabled interface reports IsEnabled() == true")
	}
	if bi.IsOnline() {
		t.Error("Newly created disabled interface reports IsOnline() == true")
	}
	if bi.IsDetached() {
		t.Error("Newly created interface reports IsDetached() == true")
	}

	bi.Enable()
	if !bi.IsEnabled() {
		t.Error("After Enable(), IsEnabled() == false")
	}
	if !bi.IsOnline() {
		t.Error("After Enable(), IsOnline() == false")
	}
	if bi.IsDetached() {
		t.Error("After Enable(), IsDetached() == true")
	}

	bi.Detach()
	if bi.IsEnabled() {
		t.Error("After Detach(), IsEnabled() == true")
	}
	if bi.IsOnline() {
		t.Error("After Detach(), IsOnline() == true")
	}
	if !bi.IsDetached() {
		t.Error("After Detach(), IsDetached() == false")
	}

	// Reset for Disable test
	bi = NewBaseInterface("test2", common.IF_TYPE_UDP, true) // Start enabled
	if !bi.Enabled {                                         // Check the Enabled field directly first
		t.Error("Newly created enabled interface reports Enabled == false")
	}
	if bi.IsEnabled() { // IsEnabled should still be false because Online is false
		t.Error("Newly created enabled interface reports IsEnabled() == true before Enable() is called")
	}

	bi.Enable()          // Explicitly enable to set Online = true
	if !bi.IsEnabled() { // Now IsEnabled should be true
		t.Error("After Enable() on initially enabled interface, IsEnabled() == false")
	}

	bi.Disable()
	if bi.Enabled { // Check Enabled field after Disable()
		t.Error("After Disable(), Enabled == true")
	}
	if bi.IsOnline() {
		t.Error("After Disable(), IsOnline() == true")
	}
	if bi.IsDetached() { // Disable doesn't detach
		t.Error("After Disable(), IsDetached() == true")
	}
}

func TestBaseInterfaceGetters(t *testing.T) {
	bi := NewBaseInterface("getterTest", common.IF_TYPE_AUTO, true)

	if bi.GetName() != "getterTest" {
		t.Errorf("GetName() = %s; want getterTest", bi.GetName())
	}
	if bi.GetType() != common.IF_TYPE_AUTO {
		t.Errorf("GetType() = %v; want %v", bi.GetType(), common.IF_TYPE_AUTO)
	}
	if bi.GetMode() != common.IF_MODE_FULL {
		t.Errorf("GetMode() = %v; want %v", bi.GetMode(), common.IF_MODE_FULL)
	}
	if bi.GetMTU() != common.DEFAULT_MTU { // Assuming default MTU
		t.Errorf("GetMTU() = %d; want %d", bi.GetMTU(), common.DEFAULT_MTU)
	}
}

func TestBaseInterfaceCallbacks(t *testing.T) {
	bi := NewBaseInterface("callbackTest", common.IF_TYPE_TCP, true)
	var wg sync.WaitGroup
	var callbackCalled bool

	callback := func(data []byte, iface common.NetworkInterface) {
		if len(data) != 5 {
			t.Errorf("Callback received data length %d; want 5", len(data))
		}
		if iface.GetName() != "callbackTest" {
			t.Errorf("Callback received interface name %s; want callbackTest", iface.GetName())
		}
		callbackCalled = true
		wg.Done()
	}

	bi.SetPacketCallback(callback)
	if bi.GetPacketCallback() == nil { // Cannot directly compare functions
		t.Error("GetPacketCallback() returned nil after SetPacketCallback()")
	}

	wg.Add(1)
	go bi.ProcessIncoming([]byte{1, 2, 3, 4, 5}) // Run in goroutine as callback might block

	// Wait for callback or timeout
	waitTimeout(&wg, 1*time.Second, t)

	if !callbackCalled {
		t.Error("Packet callback was not called after ProcessIncoming")
	}
}

func TestBaseInterfaceStats(t *testing.T) {
	bi := NewBaseInterface("statsTest", common.IF_TYPE_UDP, true)
	bi.Enable() // Need to be Online for ProcessOutgoing

	data1 := []byte{1, 2, 3}
	data2 := []byte{4, 5, 6, 7, 8}

	bi.ProcessIncoming(data1)
	if bi.RxBytes != uint64(len(data1)) {
		t.Errorf("RxBytes = %d; want %d after first ProcessIncoming", bi.RxBytes, len(data1))
	}

	bi.ProcessIncoming(data2)
	if bi.RxBytes != uint64(len(data1)+len(data2)) {
		t.Errorf("RxBytes = %d; want %d after second ProcessIncoming", bi.RxBytes, len(data1)+len(data2))
	}

	// ProcessOutgoing only updates TxBytes in BaseInterface
	err := bi.ProcessOutgoing(data1)
	if err != nil {
		t.Fatalf("ProcessOutgoing failed: %v", err)
	}
	if bi.TxBytes != uint64(len(data1)) {
		t.Errorf("TxBytes = %d; want %d after first ProcessOutgoing", bi.TxBytes, len(data1))
	}

	err = bi.ProcessOutgoing(data2)
	if err != nil {
		t.Fatalf("ProcessOutgoing failed: %v", err)
	}
	if bi.TxBytes != uint64(len(data1)+len(data2)) {
		t.Errorf("TxBytes = %d; want %d after second ProcessOutgoing", bi.TxBytes, len(data1)+len(data2))
	}
}

// Helper function to wait for a WaitGroup with a timeout
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration, t *testing.T) {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		// Completed normally
	case <-time.After(timeout):
		t.Fatal("Timed out waiting for WaitGroup")
	}
}

// Minimal mock interface for InterceptedInterface test
type mockInterface struct {
	BaseInterface
	sendCalled bool
	sendData   []byte
}

func (m *mockInterface) Send(data []byte, addr string) error {
	m.sendCalled = true
	m.sendData = data
	return nil
}

// Add other methods to satisfy the Interface interface (can be minimal/panic)
func (m *mockInterface) GetType() common.InterfaceType                  { return common.IF_TYPE_NONE }
func (m *mockInterface) GetMode() common.InterfaceMode                  { return common.IF_MODE_FULL }
func (m *mockInterface) ProcessIncoming(data []byte)                    {}
func (m *mockInterface) ProcessOutgoing(data []byte) error              { return nil }
func (m *mockInterface) SendPathRequest([]byte) error                   { return nil }
func (m *mockInterface) SendLinkPacket([]byte, []byte, time.Time) error { return nil }
func (m *mockInterface) Start() error                                   { return nil }
func (m *mockInterface) Stop() error                                    { return nil }
func (m *mockInterface) GetConn() net.Conn                              { return nil }
func (m *mockInterface) GetBandwidthAvailable() bool                    { return true }

func TestInterceptedInterface(t *testing.T) {
	mockBase := &mockInterface{}
	var interceptorCalled bool
	var interceptedData []byte

	interceptor := func(data []byte, iface common.NetworkInterface) error {
		interceptorCalled = true
		interceptedData = data
		return nil
	}

	intercepted := NewInterceptedInterface(mockBase, interceptor)

	testData := []byte("intercept me")
	err := intercepted.Send(testData, "dummy_addr")
	if err != nil {
		t.Fatalf("Intercepted Send failed: %v", err)
	}

	if !interceptorCalled {
		t.Error("Interceptor function was not called")
	}
	if !bytes.Equal(interceptedData, testData) {
		t.Errorf("Interceptor received data %x; want %x", interceptedData, testData)
	}

	if !mockBase.sendCalled {
		t.Error("Original Send function was not called")
	}
	if !bytes.Equal(mockBase.sendData, testData) {
		t.Errorf("Original Send received data %x; want %x", mockBase.sendData, testData)
	}
}
