package interfaces

import (
	"net"
	"testing"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

func TestNewAutoInterface(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := &common.InterfaceConfig{Enabled: true}
		ai, err := NewAutoInterface("autoDefault", config)
		if err != nil {
			t.Fatalf("NewAutoInterface failed with default config: %v", err)
		}
		if ai == nil {
			t.Fatal("NewAutoInterface returned nil with default config")
		}

		if ai.GetName() != "autoDefault" {
			t.Errorf("GetName() = %s; want autoDefault", ai.GetName())
		}
		if ai.GetType() != common.IF_TYPE_AUTO {
			t.Errorf("GetType() = %v; want %v", ai.GetType(), common.IF_TYPE_AUTO)
		}
		if ai.discoveryPort != DEFAULT_DISCOVERY_PORT {
			t.Errorf("discoveryPort = %d; want %d", ai.discoveryPort, DEFAULT_DISCOVERY_PORT)
		}
		if ai.dataPort != DEFAULT_DATA_PORT {
			t.Errorf("dataPort = %d; want %d", ai.dataPort, DEFAULT_DATA_PORT)
		}
		if string(ai.groupID) != "reticulum" {
			t.Errorf("groupID = %s; want reticulum", string(ai.groupID))
		}
		if ai.discoveryScope != SCOPE_LINK {
			t.Errorf("discoveryScope = %s; want %s", ai.discoveryScope, SCOPE_LINK)
		}
		if len(ai.peers) != 0 {
			t.Errorf("peers map not empty initially")
		}
	})

	t.Run("CustomConfig", func(t *testing.T) {
		config := &common.InterfaceConfig{
			Enabled: true,
			Port:    12345, // Custom discovery port
			GroupID: "customGroup",
		}
		ai, err := NewAutoInterface("autoCustom", config)
		if err != nil {
			t.Fatalf("NewAutoInterface failed with custom config: %v", err)
		}
		if ai == nil {
			t.Fatal("NewAutoInterface returned nil with custom config")
		}

		if ai.discoveryPort != 12345 {
			t.Errorf("discoveryPort = %d; want 12345", ai.discoveryPort)
		}
		if string(ai.groupID) != "customGroup" {
			t.Errorf("groupID = %s; want customGroup", string(ai.groupID))
		}
	})
}

// mockAutoInterface embeds AutoInterface but overrides methods that start goroutines
type mockAutoInterface struct {
	*AutoInterface
}

func newMockAutoInterface(name string, config *common.InterfaceConfig) (*mockAutoInterface, error) {
	ai, err := NewAutoInterface(name, config)
	if err != nil {
		return nil, err
	}

	// Initialize maps that would normally be initialized in Start()
	ai.peers = make(map[string]*Peer)
	ai.linkLocalAddrs = make([]string, 0)
	ai.adoptedInterfaces = make(map[string]string)
	ai.interfaceServers = make(map[string]*net.UDPConn)
	ai.multicastEchoes = make(map[string]time.Time)

	return &mockAutoInterface{AutoInterface: ai}, nil
}

func (m *mockAutoInterface) Start() error {
	// Don't start any goroutines
	return nil
}

func (m *mockAutoInterface) Stop() error {
	// Don't try to close connections that were never opened
	return nil
}

// mockHandlePeerAnnounce is a test-only method that doesn't handle its own locking
func (m *mockAutoInterface) mockHandlePeerAnnounce(addr *net.UDPAddr, data []byte, ifaceName string) {
	peerAddr := addr.IP.String() + "%" + addr.Zone

	for _, localAddr := range m.linkLocalAddrs {
		if peerAddr == localAddr {
			m.multicastEchoes[ifaceName] = time.Now()
			return
		}
	}

	if _, exists := m.peers[peerAddr]; !exists {
		m.peers[peerAddr] = &Peer{
			ifaceName: ifaceName,
			lastHeard: time.Now(),
		}
	} else {
		m.peers[peerAddr].lastHeard = time.Now()
	}
}

func TestAutoInterfacePeerManagement(t *testing.T) {
	// Use a shorter timeout for testing
	testTimeout := 100 * time.Millisecond

	config := &common.InterfaceConfig{Enabled: true}
	ai, err := newMockAutoInterface("autoPeerTest", config)
	if err != nil {
		t.Fatalf("Failed to create mock interface: %v", err)
	}

	// Create a done channel to signal goroutine cleanup
	done := make(chan struct{})

	// Start peer management with done channel
	go func() {
		ticker := time.NewTicker(testTimeout)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ai.mutex.Lock()
				now := time.Now()
				for addr, peer := range ai.peers {
					if now.Sub(peer.lastHeard) > testTimeout {
						delete(ai.peers, addr)
					}
				}
				ai.mutex.Unlock()
			case <-done:
				return
			}
		}
	}()

	// Ensure cleanup
	defer func() {
		close(done)
		ai.Stop()
	}()

	// Simulate receiving peer announces
	peer1AddrStr := "fe80::1%eth0"
	peer2AddrStr := "fe80::2%eth0"
	localAddrStr := "fe80::aaaa%eth0" // Simulate a local address

	peer1Addr := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}
	peer2Addr := &net.UDPAddr{IP: net.ParseIP("fe80::2"), Zone: "eth0"}
	localAddr := &net.UDPAddr{IP: net.ParseIP("fe80::aaaa"), Zone: "eth0"}

	// Add a simulated local address to avoid adding it as a peer
	ai.mutex.Lock()
	ai.linkLocalAddrs = append(ai.linkLocalAddrs, localAddrStr)
	ai.mutex.Unlock()

	t.Run("AddPeer1", func(t *testing.T) {
		ai.mutex.Lock()
		ai.mockHandlePeerAnnounce(peer1Addr, []byte("announce1"), "eth0")
		ai.mutex.Unlock()

		// Give a small amount of time for the peer to be processed
		time.Sleep(10 * time.Millisecond)

		ai.mutex.RLock()
		count := len(ai.peers)
		peer, exists := ai.peers[peer1AddrStr]
		var ifaceName string
		if exists {
			ifaceName = peer.ifaceName
		}
		ai.mutex.RUnlock()

		if count != 1 {
			t.Fatalf("Expected 1 peer, got %d", count)
		}
		if !exists {
			t.Fatalf("Peer %s not found in map", peer1AddrStr)
		}
		if ifaceName != "eth0" {
			t.Errorf("Peer %s interface name = %s; want eth0", peer1AddrStr, ifaceName)
		}
	})

	t.Run("AddPeer2", func(t *testing.T) {
		ai.mutex.Lock()
		ai.mockHandlePeerAnnounce(peer2Addr, []byte("announce2"), "eth0")
		ai.mutex.Unlock()

		// Give a small amount of time for the peer to be processed
		time.Sleep(10 * time.Millisecond)

		ai.mutex.RLock()
		count := len(ai.peers)
		_, exists := ai.peers[peer2AddrStr]
		ai.mutex.RUnlock()

		if count != 2 {
			t.Fatalf("Expected 2 peers, got %d", count)
		}
		if !exists {
			t.Fatalf("Peer %s not found in map", peer2AddrStr)
		}
	})

	t.Run("IgnoreLocalAnnounce", func(t *testing.T) {
		ai.mutex.Lock()
		ai.mockHandlePeerAnnounce(localAddr, []byte("local_announce"), "eth0")
		ai.mutex.Unlock()

		// Give a small amount of time for the peer to be processed
		time.Sleep(10 * time.Millisecond)

		ai.mutex.RLock()
		count := len(ai.peers)
		ai.mutex.RUnlock()

		if count != 2 {
			t.Fatalf("Expected 2 peers after local announce, got %d", count)
		}
	})

	t.Run("UpdatePeerTimestamp", func(t *testing.T) {
		ai.mutex.RLock()
		peer, exists := ai.peers[peer1AddrStr]
		var initialTime time.Time
		if exists {
			initialTime = peer.lastHeard
		}
		ai.mutex.RUnlock()

		if !exists {
			t.Fatalf("Peer %s not found before timestamp update", peer1AddrStr)
		}

		ai.mutex.Lock()
		ai.mockHandlePeerAnnounce(peer1Addr, []byte("announce1_again"), "eth0")
		ai.mutex.Unlock()

		// Give a small amount of time for the peer to be processed
		time.Sleep(10 * time.Millisecond)

		ai.mutex.RLock()
		peer, exists = ai.peers[peer1AddrStr]
		var updatedTime time.Time
		if exists {
			updatedTime = peer.lastHeard
		}
		ai.mutex.RUnlock()

		if !exists {
			t.Fatalf("Peer %s not found after timestamp update", peer1AddrStr)
		}

		if !updatedTime.After(initialTime) {
			t.Errorf("Peer timestamp was not updated after receiving another announce")
		}
	})

	t.Run("PeerTimeout", func(t *testing.T) {
		// Wait for peer timeout
		time.Sleep(testTimeout * 2)

		ai.mutex.RLock()
		count := len(ai.peers)
		ai.mutex.RUnlock()

		if count != 0 {
			t.Errorf("Expected all peers to timeout, got %d peers", count)
		}
	})
}
