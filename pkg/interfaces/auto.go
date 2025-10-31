package interfaces

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	DEFAULT_DISCOVERY_PORT = 29716
	DEFAULT_DATA_PORT      = 42671
	BITRATE_GUESS          = 10 * 1000 * 1000
	PEERING_TIMEOUT        = 7500 * time.Millisecond
	SCOPE_LINK             = "2"
	SCOPE_ADMIN            = "4"
	SCOPE_SITE             = "5"
	SCOPE_ORGANISATION     = "8"
	SCOPE_GLOBAL           = "e"
)

type AutoInterface struct {
	BaseInterface
	groupID           []byte
	discoveryPort     int
	dataPort          int
	discoveryScope    string
	peers             map[string]*Peer
	linkLocalAddrs    []string
	adoptedInterfaces map[string]string
	interfaceServers  map[string]net.Conn
	multicastEchoes   map[string]time.Time
	mutex             sync.RWMutex
	outboundConn      net.Conn
}

type Peer struct {
	ifaceName string
	lastHeard time.Time
	conn      net.PacketConn
}

func NewAutoInterface(name string, config *common.InterfaceConfig) (*AutoInterface, error) {
	ai := &AutoInterface{
		BaseInterface: BaseInterface{
			Name:     name,
			Mode:     common.IF_MODE_FULL,
			Type:     common.IF_TYPE_AUTO,
			Online:   false,
			Enabled:  config.Enabled,
			Detached: false,
			IN:       false,
			OUT:      false,
			MTU:      common.DEFAULT_MTU,
			Bitrate:  BITRATE_MINIMUM,
		},
		discoveryPort:     DEFAULT_DISCOVERY_PORT,
		dataPort:          DEFAULT_DATA_PORT,
		discoveryScope:    SCOPE_LINK,
		peers:             make(map[string]*Peer),
		linkLocalAddrs:    make([]string, 0),
		adoptedInterfaces: make(map[string]string),
		interfaceServers:  make(map[string]net.Conn),
		multicastEchoes:   make(map[string]time.Time),
	}

	if config.Port != 0 {
		ai.discoveryPort = config.Port
	}

	if config.GroupID != "" {
		ai.groupID = []byte(config.GroupID)
	} else {
		ai.groupID = []byte("reticulum")
	}

	return ai, nil
}

func (ai *AutoInterface) Start() error {
	// TinyGo doesn't support net.Interfaces() or multicast UDP
	// AutoInterface requires these features, so return an error
	return fmt.Errorf("AutoInterface not supported in TinyGo - requires interface enumeration and multicast UDP")
}

func (ai *AutoInterface) configureInterface(iface *net.Interface) error {
	// Not supported in TinyGo
	return fmt.Errorf("configureInterface not supported in TinyGo")
}

func (ai *AutoInterface) startDiscoveryListener(iface *net.Interface) error {
	// Multicast UDP not supported in TinyGo
	return fmt.Errorf("startDiscoveryListener not supported in TinyGo - requires multicast UDP")
}

func (ai *AutoInterface) startDataListener(iface *net.Interface) error {
	// TinyGo doesn't support UDP servers
	return fmt.Errorf("startDataListener not supported in TinyGo")
}

func (ai *AutoInterface) handleDiscovery(conn net.Conn, ifaceName string) {
	// Not used in TinyGo
	buf := make([]byte, 1024)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			log.Printf("Discovery read error: %v", err)
			continue
		}
	}
}

func (ai *AutoInterface) handleData(conn net.Conn) {
	buf := make([]byte, ai.GetMTU())
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if !ai.IsDetached() {
				log.Printf("Data read error: %v", err)
			}
			return
		}

		if callback := ai.GetPacketCallback(); callback != nil {
			callback(buf[:n], ai)
		}
	}
}

func (ai *AutoInterface) handlePeerAnnounce(addr *net.UDPAddr, ifaceName string) {
	ai.mutex.Lock()
	defer ai.mutex.Unlock()

	peerAddr := addr.IP.String()

	for _, localAddr := range ai.linkLocalAddrs {
		if peerAddr == localAddr {
			ai.multicastEchoes[ifaceName] = time.Now()
			return
		}
	}

	if _, exists := ai.peers[peerAddr]; !exists {
		ai.peers[peerAddr] = &Peer{
			ifaceName: ifaceName,
			lastHeard: time.Now(),
		}
		log.Printf("Added peer %s on %s", peerAddr, ifaceName)
	} else {
		ai.peers[peerAddr].lastHeard = time.Now()
	}
}

func (ai *AutoInterface) peerJobs() {
	ticker := time.NewTicker(PEERING_TIMEOUT)
	for range ticker.C {
		ai.mutex.Lock()
		now := time.Now()

		for addr, peer := range ai.peers {
			if now.Sub(peer.lastHeard) > PEERING_TIMEOUT {
				delete(ai.peers, addr)
				log.Printf("Removed timed out peer %s", addr)
			}
		}

		ai.mutex.Unlock()
	}
}

func (ai *AutoInterface) Send(data []byte, address string) error {
	// TinyGo doesn't support UDP outbound connections for auto-discovery
	return fmt.Errorf("Send not supported in TinyGo - requires UDP client connections")
}

func (ai *AutoInterface) Stop() error {
	ai.mutex.Lock()
	defer ai.mutex.Unlock()

	for _, server := range ai.interfaceServers {
		server.Close() // #nosec G104
	}

	if ai.outboundConn != nil {
		ai.outboundConn.Close() // #nosec G104
	}

	return nil
}
