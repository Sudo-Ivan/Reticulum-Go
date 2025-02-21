package interfaces

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"log/slog"
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
	interfaceServers  map[string]*net.UDPConn
	multicastEchoes   map[string]time.Time
	mutex             sync.RWMutex
	outboundConn      *net.UDPConn
}

type Peer struct {
	ifaceName string
	lastHeard time.Time
	conn      *net.UDPConn
}

func NewAutoInterface(name string, config *common.InterfaceConfig) (*AutoInterface, error) {
	base := &BaseInterface{
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
	}

	ai := &AutoInterface{
		BaseInterface:     *base,
		discoveryPort:     DEFAULT_DISCOVERY_PORT,
		dataPort:          DEFAULT_DATA_PORT,
		discoveryScope:    SCOPE_LINK,
		peers:             make(map[string]*Peer),
		linkLocalAddrs:    make([]string, 0),
		adoptedInterfaces: make(map[string]string),
		interfaceServers:  make(map[string]*net.UDPConn),
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
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if err := ai.configureInterface(&iface); err != nil {
			slog.Warn("Failed to configure interface", "iface", iface.Name, "err", err)
			continue
		}
	}

	if len(ai.adoptedInterfaces) == 0 {
		return fmt.Errorf("no suitable interfaces found")
	}

	go ai.peerJobs()
	return nil
}

func (ai *AutoInterface) configureInterface(iface *net.Interface) error {
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsLinkLocalUnicast() {
			ai.adoptedInterfaces[iface.Name] = ipnet.IP.String()
			ai.multicastEchoes[iface.Name] = time.Now()

			if err := ai.startDiscoveryListener(iface); err != nil {
				return err
			}

			if err := ai.startDataListener(iface); err != nil {
				return err
			}

			break
		}
	}

	return nil
}

func (ai *AutoInterface) startDiscoveryListener(iface *net.Interface) error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(fmt.Sprintf("ff%s%s::1", ai.discoveryScope, SCOPE_LINK)),
		Port: ai.discoveryPort,
		Zone: iface.Name,
	}

	conn, err := net.ListenMulticastUDP("udp6", iface, addr)
	if err != nil {
		return err
	}

	go ai.handleDiscovery(conn, iface.Name)
	return nil
}

func (ai *AutoInterface) startDataListener(iface *net.Interface) error {
	addr := &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: ai.dataPort,
		Zone: iface.Name,
	}

	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return err
	}

	ai.interfaceServers[iface.Name] = conn
	go ai.handleData(conn)
	return nil
}

func (ai *AutoInterface) handleDiscovery(conn *net.UDPConn, ifaceName string) {
	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			slog.Warn("Discovery read error", "err", err)
			continue
		}

		ai.handlePeerAnnounce(remoteAddr, buf[:n], ifaceName)
	}
}

func (ai *AutoInterface) handleData(conn *net.UDPConn) {
	buf := make([]byte, ai.GetMTU())
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !ai.IsDetached() {
				slog.Warn("Data read error", "err", err)
			}
			return
		}

		if callback := ai.GetPacketCallback(); callback != nil {
			callback(buf[:n], ai)
		}
	}
}

func (ai *AutoInterface) handlePeerAnnounce(addr *net.UDPAddr, data []byte, ifaceName string) {
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
		slog.Info("Added peer", "peer", peerAddr, "iface", ifaceName)
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
				slog.Debug("Removed timed-out peer", "peer", addr)
			}
		}

		ai.mutex.Unlock()
	}
}

func (ai *AutoInterface) Send(data []byte, address string) error {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()

	for _, peer := range ai.peers {
		addr := &net.UDPAddr{
			IP:   net.ParseIP(address),
			Port: ai.dataPort,
			Zone: peer.ifaceName,
		}

		if ai.outboundConn == nil {
			var err error
			ai.outboundConn, err = net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
			if err != nil {
				return err
			}
		}

		if _, err := ai.outboundConn.WriteToUDP(data, addr); err != nil {
			slog.Warn("Failed to send to peer", "peer", address, "err", err)
			continue
		}
	}

	return nil
}

func (ai *AutoInterface) Stop() error {
	ai.mutex.Lock()
	defer ai.mutex.Unlock()

	for _, server := range ai.interfaceServers {
		server.Close()
	}

	if ai.outboundConn != nil {
		ai.outboundConn.Close()
	}

	return nil
}
