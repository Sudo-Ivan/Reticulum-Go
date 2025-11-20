package interfaces

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
)

const (
	HW_MTU                 = 1196
	DEFAULT_DISCOVERY_PORT = 29716
	DEFAULT_DATA_PORT      = 42671
	DEFAULT_GROUP_ID       = "reticulum"
	BITRATE_GUESS          = 10 * 1000 * 1000
	PEERING_TIMEOUT        = 22 * time.Second
	ANNOUNCE_INTERVAL      = 1600 * time.Millisecond
	PEER_JOB_INTERVAL      = 4 * time.Second
	MCAST_ECHO_TIMEOUT     = 6500 * time.Millisecond
	
	SCOPE_LINK         = "2"
	SCOPE_ADMIN        = "4"
	SCOPE_SITE         = "5"
	SCOPE_ORGANISATION = "8"
	SCOPE_GLOBAL       = "e"
	
	MCAST_ADDR_TYPE_PERMANENT = "0"
	MCAST_ADDR_TYPE_TEMPORARY = "1"
)

type AutoInterface struct {
	BaseInterface
	groupID              []byte
	groupHash            []byte
	discoveryPort        int
	dataPort             int
	discoveryScope       string
	multicastAddrType    string
	mcastDiscoveryAddr   string
	ifacNetname          string
	peers                map[string]*Peer
	linkLocalAddrs       []string
	adoptedInterfaces    map[string]*AdoptedInterface
	interfaceServers     map[string]*net.UDPConn
	discoveryServers     map[string]*net.UDPConn
	multicastEchoes      map[string]time.Time
	timedOutInterfaces   map[string]time.Time
	allowedInterfaces    []string
	ignoredInterfaces    []string
	mutex                sync.RWMutex
	outboundConn         *net.UDPConn
	announceInterval     time.Duration
	peerJobInterval      time.Duration
	peeringTimeout       time.Duration
	mcastEchoTimeout     time.Duration
}

type AdoptedInterface struct {
	name          string
	linkLocalAddr string
	index         int
}

type Peer struct {
	ifaceName string
	lastHeard time.Time
	addr      *net.UDPAddr
}

func NewAutoInterface(name string, config *common.InterfaceConfig) (*AutoInterface, error) {
	groupID := DEFAULT_GROUP_ID
	if config.GroupID != "" {
		groupID = config.GroupID
	}

	discoveryScope := SCOPE_LINK
	if config.DiscoveryScope != "" {
		discoveryScope = normalizeScope(config.DiscoveryScope)
	}

	multicastAddrType := MCAST_ADDR_TYPE_TEMPORARY

	discoveryPort := DEFAULT_DISCOVERY_PORT
	if config.DiscoveryPort != 0 {
		discoveryPort = config.DiscoveryPort
	}

	dataPort := DEFAULT_DATA_PORT
	if config.DataPort != 0 {
		dataPort = config.DataPort
	}

	groupHash := sha256.Sum256([]byte(groupID))
	
	ifacNetname := hex.EncodeToString(groupHash[:])[:16]
	mcastAddr := fmt.Sprintf("ff%s%s::%s", discoveryScope, multicastAddrType, ifacNetname)

	ai := &AutoInterface{
		BaseInterface: BaseInterface{
			Name:     name,
			Mode:     common.IF_MODE_FULL,
			Type:     common.IF_TYPE_AUTO,
			Online:   false,
			Enabled:  config.Enabled,
			Detached: false,
			IN:       true,
			OUT:      false,
			MTU:      HW_MTU,
			Bitrate:  BITRATE_GUESS,
		},
		groupID:              []byte(groupID),
		groupHash:            groupHash[:],
		discoveryPort:        discoveryPort,
		dataPort:             dataPort,
		discoveryScope:       discoveryScope,
		multicastAddrType:    multicastAddrType,
		mcastDiscoveryAddr:   mcastAddr,
		ifacNetname:          ifacNetname,
		peers:                make(map[string]*Peer),
		linkLocalAddrs:       make([]string, 0),
		adoptedInterfaces:    make(map[string]*AdoptedInterface),
		interfaceServers:     make(map[string]*net.UDPConn),
		discoveryServers:     make(map[string]*net.UDPConn),
		multicastEchoes:      make(map[string]time.Time),
		timedOutInterfaces:   make(map[string]time.Time),
		allowedInterfaces:    make([]string, 0),
		ignoredInterfaces:    make([]string, 0),
		announceInterval:     ANNOUNCE_INTERVAL,
		peerJobInterval:      PEER_JOB_INTERVAL,
		peeringTimeout:       PEERING_TIMEOUT,
		mcastEchoTimeout:     MCAST_ECHO_TIMEOUT,
	}

	debug.Log(debug.DEBUG_INFO, "AutoInterface configured", "name", name, "group", groupID, "mcast_addr", mcastAddr)
	return ai, nil
}

func normalizeScope(scope string) string {
	switch scope {
	case "link", "2":
		return SCOPE_LINK
	case "admin", "4":
		return SCOPE_ADMIN
	case "site", "5":
		return SCOPE_SITE
	case "organisation", "organization", "8":
		return SCOPE_ORGANISATION
	case "global", "e":
		return SCOPE_GLOBAL
	default:
		return SCOPE_LINK
	}
}

func normalizeMulticastType(mtype string) string {
	switch mtype {
	case "permanent", "0":
		return MCAST_ADDR_TYPE_PERMANENT
	case "temporary", "1":
		return MCAST_ADDR_TYPE_TEMPORARY
	default:
		return MCAST_ADDR_TYPE_TEMPORARY
	}
}

func (ai *AutoInterface) Start() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if ai.shouldIgnoreInterface(iface.Name) {
			debug.Log(debug.DEBUG_TRACE, "Ignoring interface", "name", iface.Name)
			continue
		}

		if len(ai.allowedInterfaces) > 0 && !ai.isAllowedInterface(iface.Name) {
			debug.Log(debug.DEBUG_TRACE, "Interface not in allowed list", "name", iface.Name)
			continue
		}

		if err := ai.configureInterface(&iface); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to configure interface", "name", iface.Name, "error", err)
			continue
		}
	}

	if len(ai.adoptedInterfaces) == 0 {
		return fmt.Errorf("no suitable interfaces found")
	}

	ai.Online = true
	ai.IN = true
	ai.OUT = true

	go ai.peerJobs()
	go ai.announceLoop()
	
	debug.Log(debug.DEBUG_INFO, "AutoInterface started", "adopted", len(ai.adoptedInterfaces))
	return nil
}

func (ai *AutoInterface) shouldIgnoreInterface(name string) bool {
	ignoreList := []string{"lo", "lo0", "tun0", "awdl0", "llw0", "en5", "dummy0"}
	
	for _, ignored := range ai.ignoredInterfaces {
		if name == ignored {
			return true
		}
	}
	
	for _, ignored := range ignoreList {
		if name == ignored {
			return true
		}
	}
	
	return false
}

func (ai *AutoInterface) isAllowedInterface(name string) bool {
	for _, allowed := range ai.allowedInterfaces {
		if name == allowed {
			return true
		}
	}
	return false
}

func (ai *AutoInterface) configureInterface(iface *net.Interface) error {
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface is down")
	}

	if iface.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("loopback interface")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}

	var linkLocalAddr string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				linkLocalAddr = ipnet.IP.String()
				break
			}
		}
	}

	if linkLocalAddr == "" {
		return fmt.Errorf("no link-local IPv6 address found")
	}

	ai.mutex.Lock()
	ai.adoptedInterfaces[iface.Name] = &AdoptedInterface{
		name:          iface.Name,
		linkLocalAddr: linkLocalAddr,
		index:         iface.Index,
	}
	ai.linkLocalAddrs = append(ai.linkLocalAddrs, linkLocalAddr)
	ai.multicastEchoes[iface.Name] = time.Now()
	ai.mutex.Unlock()

	if err := ai.startDiscoveryListener(iface); err != nil {
		return fmt.Errorf("failed to start discovery listener: %v", err)
	}

	if err := ai.startDataListener(iface); err != nil {
		return fmt.Errorf("failed to start data listener: %v", err)
	}

	debug.Log(debug.DEBUG_INFO, "Configured interface", "name", iface.Name, "addr", linkLocalAddr)
	return nil
}

func (ai *AutoInterface) startDiscoveryListener(iface *net.Interface) error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(ai.mcastDiscoveryAddr),
		Port: ai.discoveryPort,
		Zone: iface.Name,
	}

	conn, err := net.ListenMulticastUDP("udp6", iface, addr)
	if err != nil {
		return err
	}

	if err := conn.SetReadBuffer(1024); err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to set discovery read buffer", "error", err)
	}

	ai.mutex.Lock()
	ai.discoveryServers[iface.Name] = conn
	ai.mutex.Unlock()

	go ai.handleDiscovery(conn, iface.Name)
	debug.Log(debug.DEBUG_VERBOSE, "Discovery listener started", "interface", iface.Name, "addr", ai.mcastDiscoveryAddr)
	return nil
}

func (ai *AutoInterface) startDataListener(iface *net.Interface) error {
	adoptedIface, exists := ai.adoptedInterfaces[iface.Name]
	if !exists {
		return fmt.Errorf("interface not adopted")
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(adoptedIface.linkLocalAddr),
		Port: ai.dataPort,
		Zone: iface.Name,
	}

	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to listen on data port", "addr", addr, "error", err)
		return err
	}

	if err := conn.SetReadBuffer(ai.MTU); err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to set data read buffer", "error", err)
	}

	ai.mutex.Lock()
	ai.interfaceServers[iface.Name] = conn
	ai.mutex.Unlock()

	go ai.handleData(conn, iface.Name)
	debug.Log(debug.DEBUG_VERBOSE, "Data listener started", "interface", iface.Name, "addr", addr)
	return nil
}

func (ai *AutoInterface) handleDiscovery(conn *net.UDPConn, ifaceName string) {
	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ai.IsOnline() {
				debug.Log(debug.DEBUG_ERROR, "Discovery read error", "interface", ifaceName, "error", err)
			}
			return
		}

		if n >= len(ai.groupHash) {
			receivedHash := buf[:len(ai.groupHash)]
			if bytes.Equal(receivedHash, ai.groupHash) {
				ai.handlePeerAnnounce(remoteAddr, ifaceName)
			} else {
				debug.Log(debug.DEBUG_TRACE, "Received discovery with mismatched group hash", "interface", ifaceName)
			}
		}
	}
}

func (ai *AutoInterface) handleData(conn *net.UDPConn, ifaceName string) {
	buf := make([]byte, ai.GetMTU())
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ai.IsOnline() {
				debug.Log(debug.DEBUG_ERROR, "Data read error", "interface", ifaceName, "error", err)
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

	peerIP := addr.IP.String()

	for _, localAddr := range ai.linkLocalAddrs {
		if peerIP == localAddr {
			ai.multicastEchoes[ifaceName] = time.Now()
			debug.Log(debug.DEBUG_TRACE, "Received own multicast echo", "interface", ifaceName)
			return
		}
	}

	peerKey := peerIP + "%" + ifaceName
	
	if peer, exists := ai.peers[peerKey]; exists {
		peer.lastHeard = time.Now()
		debug.Log(debug.DEBUG_TRACE, "Updated peer", "peer", peerIP, "interface", ifaceName)
	} else {
		ai.peers[peerKey] = &Peer{
			ifaceName: ifaceName,
			lastHeard: time.Now(),
			addr:      addr,
		}
		debug.Log(debug.DEBUG_INFO, "Discovered new peer", "peer", peerIP, "interface", ifaceName)
	}
}

func (ai *AutoInterface) announceLoop() {
	ticker := time.NewTicker(ai.announceInterval)
	defer ticker.Stop()

	for range ticker.C {
		if !ai.IsOnline() {
			return
		}
		ai.sendPeerAnnounce()
	}
}

func (ai *AutoInterface) sendPeerAnnounce() {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()

	for ifaceName, adoptedIface := range ai.adoptedInterfaces {
		mcastAddr := &net.UDPAddr{
			IP:   net.ParseIP(ai.mcastDiscoveryAddr),
			Port: ai.discoveryPort,
			Zone: ifaceName,
		}

		if ai.outboundConn == nil {
			var err error
			ai.outboundConn, err = net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
			if err != nil {
				debug.Log(debug.DEBUG_ERROR, "Failed to create outbound socket", "error", err)
				return
			}
		}

		if _, err := ai.outboundConn.WriteToUDP(ai.groupHash, mcastAddr); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to send peer announce", "interface", ifaceName, "error", err)
		} else {
			debug.Log(debug.DEBUG_TRACE, "Sent peer announce", "interface", adoptedIface.name)
		}
	}
}

func (ai *AutoInterface) peerJobs() {
	ticker := time.NewTicker(ai.peerJobInterval)
	defer ticker.Stop()

	for range ticker.C {
		if !ai.IsOnline() {
			return
		}

		ai.mutex.Lock()
		now := time.Now()

		for peerKey, peer := range ai.peers {
			if now.Sub(peer.lastHeard) > ai.peeringTimeout {
				delete(ai.peers, peerKey)
				debug.Log(debug.DEBUG_VERBOSE, "Removed timed out peer", "peer", peerKey)
			}
		}

		for ifaceName, echoTime := range ai.multicastEchoes {
			if now.Sub(echoTime) > ai.mcastEchoTimeout {
				if _, exists := ai.timedOutInterfaces[ifaceName]; !exists {
					debug.Log(debug.DEBUG_INFO, "Interface timed out", "interface", ifaceName)
					ai.timedOutInterfaces[ifaceName] = now
				}
			} else {
				delete(ai.timedOutInterfaces, ifaceName)
			}
		}

		ai.mutex.Unlock()
	}
}

func (ai *AutoInterface) Send(data []byte, address string) error {
	if !ai.IsOnline() {
		return fmt.Errorf("interface offline")
	}

	ai.mutex.RLock()
	defer ai.mutex.RUnlock()

	if len(ai.peers) == 0 {
		debug.Log(debug.DEBUG_TRACE, "No peers available for sending")
		return nil
	}

	if ai.outboundConn == nil {
		var err error
		ai.outboundConn, err = net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
		if err != nil {
			return fmt.Errorf("failed to create outbound socket: %v", err)
		}
	}

	sentCount := 0
	for _, peer := range ai.peers {
		targetAddr := &net.UDPAddr{
			IP:   peer.addr.IP,
			Port: ai.dataPort,
			Zone: peer.ifaceName,
		}

		if _, err := ai.outboundConn.WriteToUDP(data, targetAddr); err != nil {
			debug.Log(debug.DEBUG_VERBOSE, "Failed to send to peer", "interface", peer.ifaceName, "error", err)
			continue
		}
		sentCount++
	}

	if sentCount > 0 {
		debug.Log(debug.DEBUG_TRACE, "Sent data to peers", "count", sentCount, "bytes", len(data))
	}

	return nil
}

func (ai *AutoInterface) Stop() error {
	ai.mutex.Lock()
	defer ai.mutex.Unlock()

	ai.Online = false
	ai.IN = false
	ai.OUT = false

	for _, server := range ai.interfaceServers {
		server.Close() // #nosec G104
	}

	for _, server := range ai.discoveryServers {
		server.Close() // #nosec G104
	}

	if ai.outboundConn != nil {
		ai.outboundConn.Close() // #nosec G104
	}

	debug.Log(debug.DEBUG_INFO, "AutoInterface stopped")
	return nil
}
