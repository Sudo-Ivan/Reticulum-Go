package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/cryptography"
	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/pathfinder"
	"github.com/Sudo-Ivan/reticulum-go/pkg/resolver"
	"github.com/Sudo-Ivan/reticulum-go/pkg/resource"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	CURVE = "Curve25519"

	ECPUBSIZE                     = 64
	KEYSIZE                       = 32
	LINK_MTU_SIZE                 = 3
	MTU_BYTEMASK                  = 0xFFFFFF
	MODE_BYTEMASK                 = 0xE0
	
	ESTABLISHMENT_TIMEOUT_PER_HOP = 6
	KEEPALIVE_TIMEOUT_FACTOR      = 4
	STALE_GRACE                   = 2
	KEEPALIVE                     = 360
	STALE_TIME                    = 720

	ACCEPT_NONE = 0x00
	ACCEPT_ALL  = 0x01
	ACCEPT_APP  = 0x02

	STATUS_PENDING   = 0x00
	STATUS_HANDSHAKE = 0x01
	STATUS_ACTIVE    = 0x02
	STATUS_CLOSED    = 0x03
	STATUS_FAILED    = 0x04

	PROVE_NONE = 0x00
	PROVE_ALL  = 0x01
	PROVE_APP  = 0x02

	MODE_AES128_CBC = 0x00
	MODE_AES256_CBC = 0x01
	MODE_DEFAULT    = MODE_AES256_CBC

	WATCHDOG_MIN_SLEEP = 0.025
	WATCHDOG_INTERVAL  = 0.1
)

type Link struct {
	mutex            sync.RWMutex
	destination      *destination.Destination
	status           byte
	networkInterface common.NetworkInterface
	establishedAt    time.Time
	lastInbound      time.Time
	lastOutbound     time.Time
	lastDataReceived time.Time
	lastDataSent     time.Time
	pathFinder       *pathfinder.PathFinder

	remoteIdentity *identity.Identity
	sessionKey     []byte
	linkID         []byte

	rtt               float64
	establishmentRate float64

	establishedCallback func(*Link)
	closedCallback      func(*Link)
	packetCallback      func([]byte, *packet.Packet)
	identifiedCallback  func(*Link, *identity.Identity)

	teardownReason byte
	hmacKey        []byte
	transport      *transport.Transport

	rssi                      float64
	snr                       float64
	q                         float64
	resourceCallback          func(interface{}) bool
	resourceStartedCallback   func(interface{})
	resourceConcludedCallback func(interface{})
	resourceStrategy          byte
	proofStrategy             byte
	proofCallback             func(*packet.Packet) bool
	trackPhyStats             bool

	watchdogLock         bool
	watchdogActive       bool
	establishmentTimeout time.Duration
	keepalive            time.Duration
	staleTime            time.Duration
	initiator            bool
	
	prv           []byte
	sigPriv       ed25519.PrivateKey
	pub           []byte
	sigPub        ed25519.PublicKey
	peerPub       []byte
	peerSigPub    ed25519.PublicKey
	sharedKey     []byte
	derivedKey    []byte
	mode          byte
	mtu           int
	requestTime   time.Time
	requestPacket *packet.Packet
}

func NewLink(dest *destination.Destination, transport *transport.Transport, networkIface common.NetworkInterface, establishedCallback func(*Link), closedCallback func(*Link)) *Link {
	return &Link{
		destination:         dest,
		status:              STATUS_PENDING,
		transport:           transport,
		networkInterface:    networkIface,
		establishedCallback: establishedCallback,
		closedCallback:      closedCallback,
		establishedAt:       time.Time{}, // Zero time until established
		lastInbound:         time.Time{},
		lastOutbound:        time.Time{},
		lastDataReceived:    time.Time{},
		lastDataSent:        time.Time{},
		pathFinder:          pathfinder.NewPathFinder(),

		watchdogLock:         false,
		watchdogActive:       false,
		establishmentTimeout: time.Duration(ESTABLISHMENT_TIMEOUT_PER_HOP * float64(time.Second)),
		keepalive:            time.Duration(KEEPALIVE * float64(time.Second)),
		staleTime:            time.Duration(STALE_TIME * float64(time.Second)),
		initiator:            false,
	}
}

func (l *Link) Establish() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_PENDING {
		log.Printf("[DEBUG-3] Cannot establish link: invalid status %d", l.status)
		return errors.New("link already established or failed")
	}

	destPublicKey := l.destination.GetPublicKey()
	if destPublicKey == nil {
		log.Printf("[DEBUG-3] Cannot establish link: destination has no public key")
		return errors.New("destination has no public key")
	}

	// Generate link ID for this connection
	l.linkID = make([]byte, 16)
	if _, err := rand.Read(l.linkID); err != nil {
		log.Printf("[DEBUG-3] Failed to generate link ID: %v", err)
		return fmt.Errorf("failed to generate link ID: %w", err)
	}
	l.initiator = true

	log.Printf("[DEBUG-4] Creating link request packet for destination %x with link ID %x", destPublicKey[:8], l.linkID[:8])

	p := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeLinkReq,
		TransportType:   0,
		Context:         packet.ContextLinkIdentify,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            l.linkID,
		CreateReceipt:   true,
	}

	if err := p.Pack(); err != nil {
		log.Printf("[DEBUG-3] Failed to pack link request packet: %v", err)
		return err
	}

	log.Printf("[DEBUG-4] Sending link request packet with ID %x", l.linkID[:8])
	return l.transport.SendPacket(p)
}

func (l *Link) Identify(id *identity.Identity) error {
	if !l.IsActive() {
		return errors.New("link not active")
	}

	p := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextLinkIdentify,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            id.GetPublicKey(),
		CreateReceipt:   true,
	}

	if err := p.Pack(); err != nil {
		return err
	}

	return l.transport.SendPacket(p)
}

func (l *Link) HandleIdentification(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if len(data) < ed25519.PublicKeySize+ed25519.SignatureSize {
		log.Printf("[DEBUG-3] Invalid identification data length: %d bytes", len(data))
		return errors.New("invalid identification data length")
	}

	pubKey := data[:ed25519.PublicKeySize]
	signature := data[ed25519.PublicKeySize:]

	log.Printf("[DEBUG-4] Processing identification from public key %x", pubKey[:8])

	remoteIdentity := identity.FromPublicKey(pubKey)
	if remoteIdentity == nil {
		log.Printf("[DEBUG-3] Invalid remote identity from public key %x", pubKey[:8])
		return errors.New("invalid remote identity")
	}

	signData := append(l.linkID, pubKey...)
	if !remoteIdentity.Verify(signData, signature) {
		log.Printf("[DEBUG-3] Invalid signature from remote identity %x", pubKey[:8])
		return errors.New("invalid signature")
	}

	log.Printf("[DEBUG-4] Remote identity verified successfully: %x", pubKey[:8])
	l.remoteIdentity = remoteIdentity

	if l.identifiedCallback != nil {
		log.Printf("[DEBUG-4] Executing identified callback for remote identity %x", pubKey[:8])
		l.identifiedCallback(l, remoteIdentity)
	}

	return nil
}

func (l *Link) Request(path string, data []byte, timeout time.Duration) (*RequestReceipt, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		return nil, errors.New("link not active")
	}

	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, err
	}

	// Create request message
	reqMsg := make([]byte, 0)
	reqMsg = append(reqMsg, requestID...)
	reqMsg = append(reqMsg, []byte(path)...)
	if data != nil {
		reqMsg = append(reqMsg, data...)
	}

	receipt := &RequestReceipt{
		requestID: requestID,
		status:    STATUS_PENDING,
		sentAt:    time.Now(),
	}

	// Send request
	err := l.SendPacket(reqMsg)
	if err != nil {
		return nil, err
	}

	// Set timeout
	if timeout > 0 {
		go func() {
			time.Sleep(timeout)
			l.mutex.Lock()
			if receipt.status == STATUS_PENDING {
				receipt.status = STATUS_FAILED
			}
			l.mutex.Unlock()
		}()
	}

	return receipt, nil
}

type RequestReceipt struct {
	mutex      sync.RWMutex
	requestID  []byte
	status     byte
	sentAt     time.Time
	receivedAt time.Time
	response   []byte
}

func (r *RequestReceipt) GetRequestID() []byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return append([]byte{}, r.requestID...)
}

func (r *RequestReceipt) GetStatus() byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.status
}

func (r *RequestReceipt) GetResponse() []byte {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if r.response == nil {
		return nil
	}
	return append([]byte{}, r.response...)
}

func (r *RequestReceipt) GetResponseTime() float64 {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if r.receivedAt.IsZero() {
		return 0
	}
	return r.receivedAt.Sub(r.sentAt).Seconds()
}

func (r *RequestReceipt) Concluded() bool {
	status := r.GetStatus()
	return status == STATUS_ACTIVE || status == STATUS_FAILED
}

func (l *Link) TrackPhyStats(track bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.trackPhyStats = track
}

func (l *Link) UpdatePhyStats(rssi, snr, q float64) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.trackPhyStats {
		l.rssi = rssi
		l.snr = snr
		l.q = q
	}
}

func (l *Link) GetRSSI() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if !l.trackPhyStats {
		return 0
	}
	return l.rssi
}

func (l *Link) GetSNR() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if !l.trackPhyStats {
		return 0
	}
	return l.snr
}

func (l *Link) GetQ() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if !l.trackPhyStats {
		return 0
	}
	return l.q
}

func (l *Link) GetEstablishmentRate() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.establishmentRate
}

func (l *Link) GetAge() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if l.establishedAt.IsZero() {
		return 0
	}
	return time.Since(l.establishedAt).Seconds()
}

func (l *Link) NoInboundFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if l.lastInbound.IsZero() {
		return 0
	}
	return time.Since(l.lastInbound).Seconds()
}

func (l *Link) NoOutboundFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	if l.lastOutbound.IsZero() {
		return 0
	}
	return time.Since(l.lastOutbound).Seconds()
}

func (l *Link) NoDataFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	lastData := l.lastDataReceived
	if l.lastDataSent.After(lastData) {
		lastData = l.lastDataSent
	}
	if lastData.IsZero() {
		return 0
	}
	return time.Since(lastData).Seconds()
}

func (l *Link) InactiveFor() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	lastActivity := l.lastInbound
	if l.lastOutbound.After(lastActivity) {
		lastActivity = l.lastOutbound
	}
	if lastActivity.IsZero() {
		return 0
	}
	return time.Since(lastActivity).Seconds()
}

func (l *Link) GetRemoteIdentity() *identity.Identity {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.remoteIdentity
}

func (l *Link) Teardown() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status == STATUS_ACTIVE {
		l.status = STATUS_CLOSED
		if l.closedCallback != nil {
			l.closedCallback(l)
		}
	}
}

func (l *Link) SetLinkClosedCallback(callback func(*Link)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.closedCallback = callback
}

func (l *Link) SetPacketCallback(callback func([]byte, *packet.Packet)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.packetCallback = callback
}

func (l *Link) SetResourceCallback(callback func(interface{}) bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceCallback = callback
}

func (l *Link) SetResourceStartedCallback(callback func(interface{})) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceStartedCallback = callback
}

func (l *Link) SetResourceConcludedCallback(callback func(interface{})) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceConcludedCallback = callback
}

func (l *Link) SetRemoteIdentifiedCallback(callback func(*Link, *identity.Identity)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.identifiedCallback = callback
}

func (l *Link) SetResourceStrategy(strategy byte) error {
	if strategy != ACCEPT_NONE && strategy != ACCEPT_ALL && strategy != ACCEPT_APP {
		return errors.New("unsupported resource strategy")
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.resourceStrategy = strategy
	return nil
}

func (l *Link) SendPacket(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		log.Printf("[DEBUG-3] Cannot send packet: link not active (status: %d)", l.status)
		return errors.New("link not active")
	}

	log.Printf("[DEBUG-4] Encrypting packet of %d bytes", len(data))
	encrypted, err := l.encrypt(data)
	if err != nil {
		log.Printf("[DEBUG-3] Failed to encrypt packet: %v", err)
		return err
	}

	p := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeData,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            encrypted,
		CreateReceipt:   false,
	}

	if err := p.Pack(); err != nil {
		return err
	}

	log.Printf("[DEBUG-4] Sending encrypted packet of %d bytes", len(encrypted))
	l.lastOutbound = time.Now()
	l.lastDataSent = time.Now()

	return l.transport.SendPacket(p)
}

func (l *Link) HandleInbound(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		log.Printf("[DEBUG-3] Dropping inbound packet: link not active (status: %d)", l.status)
		return errors.New("link not active")
	}

	// Decode and log packet details
	l.decodePacket(data)

	// Decrypt if we have a session key
	if l.sessionKey != nil {
		decrypted, err := l.decrypt(data)
		if err != nil {
			log.Printf("[DEBUG-3] Failed to decrypt packet: %v", err)
			return err
		}
		data = decrypted
	}

	l.lastInbound = time.Now()
	l.lastDataReceived = time.Now()

	if l.packetCallback != nil {
		l.packetCallback(data, nil)
	}

	return nil
}

func (l *Link) encrypt(data []byte) ([]byte, error) {
	if l.sessionKey == nil {
		return nil, errors.New("no session key available")
	}

	block, err := aes.NewCipher(l.sessionKey)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv) // #nosec G407
	ciphertext := make([]byte, len(padtext))
	mode.CryptBlocks(ciphertext, padtext)

	// Prepend IV to ciphertext
	return append(iv, ciphertext...), nil
}

func (l *Link) decrypt(data []byte) ([]byte, error) {
	if l.sessionKey == nil {
		return nil, errors.New("no session key available")
	}

	block, err := aes.NewCipher(l.sessionKey)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New("invalid padding")
	}

	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}

func (l *Link) GetRTT() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.rtt
}

func (l *Link) SetRTT(rtt float64) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.rtt = rtt
}

func (l *Link) GetStatus() byte {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.status
}

func (l *Link) IsActive() bool {
	return l.GetStatus() == STATUS_ACTIVE
}

func (l *Link) SendResource(res *resource.Resource) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		l.teardownReason = STATUS_FAILED
		return errors.New("link not active")
	}

	// Activate the resource
	res.Activate()

	// Send the resource data as packets
	buffer := make([]byte, resource.DEFAULT_SEGMENT_SIZE)
	for {
		n, err := res.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			l.teardownReason = STATUS_FAILED
			return fmt.Errorf("error reading resource: %v", err)
		}

		if err := l.SendPacket(buffer[:n]); err != nil {
			l.teardownReason = STATUS_FAILED
			return fmt.Errorf("error sending resource packet: %v", err)
		}
	}

	return nil
}

func (l *Link) maintainLink() {
	ticker := time.NewTicker(time.Second * KEEPALIVE)
	defer ticker.Stop()

	for range ticker.C {
		if l.status != STATUS_ACTIVE {
			return
		}

		inactiveTime := l.InactiveFor()
		if inactiveTime > float64(STALE_TIME) {
			l.mutex.Lock()
			l.teardownReason = STATUS_FAILED
			l.mutex.Unlock()
			l.Teardown()
			return
		}

		noDataTime := l.NoDataFor()
		if noDataTime > float64(KEEPALIVE) {
			l.mutex.Lock()
			err := l.SendPacket([]byte{})
			if err != nil {
				l.teardownReason = STATUS_FAILED
				l.mutex.Unlock()
				l.Teardown()
				return
			}
			l.mutex.Unlock()
		}
	}
}

func (l *Link) Start() {
	go l.maintainLink()
}

func (l *Link) SetProofStrategy(strategy byte) error {
	if strategy != PROVE_NONE && strategy != PROVE_ALL && strategy != PROVE_APP {
		return errors.New("invalid proof strategy")
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.proofStrategy = strategy
	return nil
}

func (l *Link) SetProofCallback(callback func(*packet.Packet) bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.proofCallback = callback
}

func (l *Link) HandleProofRequest(packet *packet.Packet) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	switch l.proofStrategy {
	case PROVE_NONE:
		return false
	case PROVE_ALL:
		return true
	case PROVE_APP:
		if l.proofCallback != nil {
			return l.proofCallback(packet)
		}
		return false
	default:
		return false
	}
}

func (l *Link) decodePacket(data []byte) {
	if len(data) < 1 {
		log.Printf("[DEBUG-7] Invalid packet: zero length")
		return
	}

	packetType := data[0]
	log.Printf("[DEBUG-7] Packet Analysis:")
	log.Printf("[DEBUG-7] - Size: %d bytes", len(data))
	log.Printf("[DEBUG-7] - Type: 0x%02x", packetType)

	switch packetType {
	case packet.PacketTypeData:
		log.Printf("[DEBUG-7] - Type Description: Data Packet")
		if len(data) > 1 {
			log.Printf("[DEBUG-7] - Payload Size: %d bytes", len(data)-1)
		}

	case packet.PacketTypeLinkReq:
		log.Printf("[DEBUG-7] - Type Description: Link Management")
		if len(data) > 32 {
			log.Printf("[DEBUG-7] - Link ID: %x", data[1:33])
		}

	case packet.PacketTypeAnnounce:
		log.Printf("[DEBUG-7] Received announce packet (%d bytes)", len(data))
		if len(data) < packet.MinAnnounceSize {
			log.Printf("[DEBUG-3] Announce packet too short: %d bytes", len(data))
			return
		}

		destHash := data[2:18]
		encKey := data[18:50]
		signKey := data[50:82]
		nameHash := data[82:92]
		randomHash := data[92:102]
		signature := data[102:166]
		appData := data[166:]

		pubKey := append(encKey, signKey...)

		validationData := make([]byte, 0, 164)
		validationData = append(validationData, destHash...)
		validationData = append(validationData, encKey...)
		validationData = append(validationData, signKey...)
		validationData = append(validationData, nameHash...)
		validationData = append(validationData, randomHash...)

		if identity.ValidateAnnounce(validationData, destHash, pubKey, signature, appData) {
			log.Printf("[DEBUG-4] Valid announce from %x", pubKey[:8])
			if err := l.transport.HandleAnnounce(destHash, l.networkInterface); err != nil {
				log.Printf("[DEBUG-3] Failed to handle announce: %v", err)
			}
		} else {
			log.Printf("[DEBUG-3] Invalid announce signature from %x", pubKey[:8])
		}

	case packet.PacketTypeProof:
		log.Printf("[DEBUG-7] - Type Description: RNS Discovery")
		if len(data) > 17 {
			searchHash := data[1:17]
			log.Printf("[DEBUG-7] - Searching for Hash: %x", searchHash)

			if id, err := resolver.ResolveIdentity(hex.EncodeToString(searchHash)); err == nil {
				log.Printf("[DEBUG-7] - Found matching identity: %s", id.GetHexHash())
			}
		}

	default:
		log.Printf("[DEBUG-7] - Type Description: Unknown (0x%02x)", packetType)
		log.Printf("[DEBUG-7] - Raw Hex: %x", data)
	}
}

// Helper function for min of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (l *Link) startWatchdog() {
	if l.watchdogActive {
		return
	}

	l.watchdogActive = true
	go l.watchdog()
}

func (l *Link) watchdog() {
	for l.status != STATUS_CLOSED {
		l.mutex.Lock()
		if l.watchdogLock {
			l.mutex.Unlock()
			time.Sleep(time.Duration(WATCHDOG_MIN_SLEEP * float64(time.Second)))
			continue
		}

		var sleepTime float64 = WATCHDOG_INTERVAL

		switch l.status {
		case STATUS_ACTIVE:
			lastActivity := l.lastInbound
			if l.lastOutbound.After(lastActivity) {
				lastActivity = l.lastOutbound
			}

			if time.Since(lastActivity) > l.keepalive {
				if l.initiator {
					if err := l.SendPacket([]byte{}); err != nil { // #nosec G104
						log.Printf("[DEBUG-3] Failed to send keepalive packet: %v", err)
					}
				}

				if time.Since(lastActivity) > l.staleTime {
					l.status = STATUS_CLOSED
					l.teardownReason = STATUS_FAILED
					if l.closedCallback != nil {
						l.closedCallback(l)
					}
				}
			}
		}

		l.mutex.Unlock()
		time.Sleep(time.Duration(sleepTime * float64(time.Second)))
	}
	l.watchdogActive = false
}

func (l *Link) Validate(signature, message []byte) bool {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	
	if l.remoteIdentity == nil {
		return false
	}
	
	return l.remoteIdentity.Verify(message, signature)
}

func (l *Link) generateEphemeralKeys() error {
	priv, pub, err := cryptography.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}
	l.prv = priv
	l.pub = pub

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}
	l.sigPriv = privKey
	l.sigPub = pubKey

	return nil
}

func signallingBytes(mtu int, mode byte) []byte {
	bytes := make([]byte, LINK_MTU_SIZE)
	bytes[0] = byte((mtu >> 16) & 0xFF)
	bytes[1] = byte((mtu >> 8) & 0xFF)
	bytes[2] = byte(mtu & 0xFF)
	bytes[0] |= (mode << 5)
	return bytes
}

func (l *Link) SendLinkRequest() error {
	if err := l.generateEphemeralKeys(); err != nil {
		return err
	}

	l.mode = MODE_DEFAULT
	l.mtu = 500

	signalling := signallingBytes(l.mtu, l.mode)
	requestData := make([]byte, 0, ECPUBSIZE+LINK_MTU_SIZE)
	requestData = append(requestData, l.pub...)
	requestData = append(requestData, l.sigPub...)
	requestData = append(requestData, signalling...)

	pkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeLinkReq,
		TransportType:   0,
		Context:         packet.ContextNone,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: l.destination.GetType(),
		DestinationHash: l.destination.GetHash(),
		Data:            requestData,
		CreateReceipt:   false,
	}

	if err := pkt.Pack(); err != nil {
		return fmt.Errorf("failed to pack link request: %w", err)
	}

	l.linkID = linkIDFromPacket(pkt)
	l.requestPacket = pkt
	l.requestTime = time.Now()
	l.status = STATUS_PENDING

	if err := l.transport.SendPacket(pkt); err != nil {
		return fmt.Errorf("failed to send link request: %w", err)
	}

	log.Printf("[DEBUG-3] Link request sent, link_id=%x", l.linkID)
	return nil
}

func linkIDFromPacket(pkt *packet.Packet) []byte {
	hashablePart := make([]byte, 0, 1+16+1+ECPUBSIZE)
	hashablePart = append(hashablePart, pkt.Raw[0])
	
	if pkt.HeaderType == packet.HeaderType2 {
		startIndex := 18
		endIndex := startIndex + 16 + 1 + ECPUBSIZE
		if len(pkt.Raw) >= endIndex {
			hashablePart = append(hashablePart, pkt.Raw[startIndex:endIndex]...)
		}
	} else {
		startIndex := 2
		endIndex := startIndex + 16 + 1 + ECPUBSIZE
		if len(pkt.Raw) >= endIndex {
			hashablePart = append(hashablePart, pkt.Raw[startIndex:endIndex]...)
		}
	}
	return identity.TruncatedHash(hashablePart)
}

func (l *Link) HandleLinkRequest(pkt *packet.Packet, ownerIdentity *identity.Identity) error {
	if len(pkt.Data) < ECPUBSIZE {
		return errors.New("link request data too short")
	}

	peerPub := pkt.Data[0:KEYSIZE]
	peerSigPub := pkt.Data[KEYSIZE : ECPUBSIZE]

	l.peerPub = peerPub
	l.peerSigPub = peerSigPub
	l.linkID = linkIDFromPacket(pkt)
	l.initiator = false

	if len(pkt.Data) >= ECPUBSIZE+LINK_MTU_SIZE {
		mtuBytes := pkt.Data[ECPUBSIZE : ECPUBSIZE+LINK_MTU_SIZE]
		l.mtu = (int(mtuBytes[0]&0x1F) << 16) | (int(mtuBytes[1]) << 8) | int(mtuBytes[2])
		l.mode = (mtuBytes[0] & MODE_BYTEMASK) >> 5
		log.Printf("[DEBUG-4] Link request includes MTU: %d, mode: %d", l.mtu, l.mode)
	} else {
		l.mtu = 500
		l.mode = MODE_DEFAULT
	}

	if err := l.generateEphemeralKeys(); err != nil {
		return err
	}

	if err := l.performHandshake(); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	if err := l.sendLinkProof(ownerIdentity); err != nil {
		return fmt.Errorf("failed to send link proof: %w", err)
	}

	l.status = STATUS_ACTIVE
	l.establishedAt = time.Now()
	log.Printf("[DEBUG-3] Link established (responder), link_id=%x", l.linkID)

	if l.establishedCallback != nil {
		go l.establishedCallback(l)
	}

	return nil
}

func (l *Link) performHandshake() error {
	if len(l.peerPub) != KEYSIZE {
		return errors.New("invalid peer public key length")
	}

	sharedSecret, err := cryptography.DeriveSharedSecret(l.prv, l.peerPub)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}
	l.sharedKey = sharedSecret

	var derivedKeyLength int
	if l.mode == MODE_AES128_CBC {
		derivedKeyLength = 32
	} else if l.mode == MODE_AES256_CBC {
		derivedKeyLength = 64
	} else {
		return fmt.Errorf("invalid link mode: %d", l.mode)
	}

	derivedKey, err := cryptography.DeriveKey(l.sharedKey, l.linkID, nil, derivedKeyLength)
	if err != nil {
		return fmt.Errorf("HKDF failed: %w", err)
	}
	l.derivedKey = derivedKey

	if len(derivedKey) >= 32 {
		l.sessionKey = derivedKey[0:32]
	}
	if len(derivedKey) >= 64 {
		l.hmacKey = derivedKey[32:64]
	}

	l.status = STATUS_HANDSHAKE
	log.Printf("[DEBUG-4] Handshake completed, derived %d bytes of key material", len(derivedKey))
	return nil
}

func (l *Link) sendLinkProof(ownerIdentity *identity.Identity) error {
	proofPkt, err := l.GenerateLinkProof(ownerIdentity)
	if err != nil {
		return err
	}

	if l.transport != nil {
		if err := l.transport.SendPacket(proofPkt); err != nil {
			return fmt.Errorf("failed to send link proof: %w", err)
		}
		log.Printf("[DEBUG-3] Link proof sent, link_id=%x", l.linkID)
	}

	return nil
}

func (l *Link) GenerateLinkProof(ownerIdentity *identity.Identity) (*packet.Packet, error) {
	signalling := signallingBytes(l.mtu, l.mode)
	
	ownerSigPub := ownerIdentity.GetPublicKey()[KEYSIZE:ECPUBSIZE]
	
	signedData := make([]byte, 0, len(l.linkID)+KEYSIZE+len(ownerSigPub)+len(signalling))
	signedData = append(signedData, l.linkID...)
	signedData = append(signedData, l.pub...)
	signedData = append(signedData, ownerSigPub...)
	signedData = append(signedData, signalling...)

	signature := ownerIdentity.Sign(signedData)

	proofData := make([]byte, 0, len(signature)+KEYSIZE+len(signalling))
	proofData = append(proofData, signature...)
	proofData = append(proofData, l.pub...)
	proofData = append(proofData, signalling...)

	proofPkt := &packet.Packet{
		HeaderType:      packet.HeaderType1,
		PacketType:      packet.PacketTypeProof,
		TransportType:   0,
		Context:         packet.ContextLRProof,
		ContextFlag:     packet.FlagUnset,
		Hops:            0,
		DestinationType: 0x03,
		DestinationHash: l.linkID,
		Data:            proofData,
		CreateReceipt:   false,
		Link:            l,
	}

	if err := proofPkt.Pack(); err != nil {
		return nil, fmt.Errorf("failed to pack link proof: %w", err)
	}

	return proofPkt, nil
}

func (l *Link) ValidateLinkProof(pkt *packet.Packet) error {
	if l.status != STATUS_PENDING {
		return fmt.Errorf("invalid link status for proof validation: %d", l.status)
	}

	if len(pkt.Data) < identity.SIGLENGTH/8+KEYSIZE {
		return errors.New("link proof data too short")
	}

	signature := pkt.Data[0 : identity.SIGLENGTH/8]
	peerPub := pkt.Data[identity.SIGLENGTH/8 : identity.SIGLENGTH/8+KEYSIZE]

	signalling := []byte{0, 0, 0}
	if len(pkt.Data) >= identity.SIGLENGTH/8+KEYSIZE+LINK_MTU_SIZE {
		signalling = pkt.Data[identity.SIGLENGTH/8+KEYSIZE : identity.SIGLENGTH/8+KEYSIZE+LINK_MTU_SIZE]
		mtu := (int(signalling[0]&0x1F) << 16) | (int(signalling[1]) << 8) | int(signalling[2])
		mode := (signalling[0] & MODE_BYTEMASK) >> 5
		l.mtu = mtu
		l.mode = mode
		log.Printf("[DEBUG-4] Link proof includes MTU: %d, mode: %d", mtu, mode)
	}

	l.peerPub = peerPub
	if l.destination != nil && l.destination.GetIdentity() != nil {
		destIdent := l.destination.GetIdentity()
		pubKey := destIdent.GetPublicKey()
		if len(pubKey) >= ECPUBSIZE {
			l.peerSigPub = pubKey[KEYSIZE:ECPUBSIZE]
		}
	}

	signedData := make([]byte, 0, len(l.linkID)+KEYSIZE+len(l.peerSigPub)+len(signalling))
	signedData = append(signedData, l.linkID...)
	signedData = append(signedData, peerPub...)
	signedData = append(signedData, l.peerSigPub...)
	signedData = append(signedData, signalling...)

	if l.destination == nil || l.destination.GetIdentity() == nil {
		return errors.New("no destination identity for proof validation")
	}

	if !l.destination.GetIdentity().Verify(signedData, signature) {
		return errors.New("link proof signature validation failed")
	}

	if err := l.performHandshake(); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	l.rtt = time.Since(l.requestTime).Seconds()
	l.status = STATUS_ACTIVE
	l.establishedAt = time.Now()

	log.Printf("[DEBUG-3] Link established (initiator), link_id=%x, RTT=%.3fs", l.linkID, l.rtt)

	if l.establishedCallback != nil {
		go l.establishedCallback(l)
	}

	return nil
}
