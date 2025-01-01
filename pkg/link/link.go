package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
	"github.com/Sudo-Ivan/reticulum-go/pkg/resource"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	CURVE = "Curve25519"

	ESTABLISHMENT_TIMEOUT_PER_HOP = 6
	KEEPALIVE_TIMEOUT_FACTOR      = 4
	STALE_GRACE                   = 2
	KEEPALIVE                     = 360
	STALE_TIME                    = 720

	ACCEPT_NONE = 0x00
	ACCEPT_ALL  = 0x01
	ACCEPT_APP  = 0x02

	STATUS_PENDING = 0x00
	STATUS_ACTIVE  = 0x01
	STATUS_CLOSED  = 0x02
	STATUS_FAILED  = 0x03

	PACKET_TYPE_DATA     = 0x00
	PACKET_TYPE_LINK     = 0x01
	PACKET_TYPE_IDENTIFY = 0x02

	PROVE_NONE = 0x00
	PROVE_ALL  = 0x01
	PROVE_APP  = 0x02
)

type Link struct {
	mutex            sync.RWMutex
	destination      *destination.Destination
	status           byte
	establishedAt    time.Time
	lastInbound      time.Time
	lastOutbound     time.Time
	lastDataReceived time.Time
	lastDataSent     time.Time

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
}

func NewLink(dest *destination.Destination, transport *transport.Transport, establishedCallback func(*Link), closedCallback func(*Link)) *Link {
	return &Link{
		destination:         dest,
		status:              STATUS_PENDING,
		transport:           transport,
		establishedCallback: establishedCallback,
		closedCallback:      closedCallback,
		establishedAt:       time.Time{}, // Zero time until established
		lastInbound:         time.Time{},
		lastOutbound:        time.Time{},
		lastDataReceived:    time.Time{},
		lastDataSent:        time.Time{},
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

	log.Printf("[DEBUG-4] Creating link request packet for destination %x", destPublicKey[:8])

	// Create link request packet
	p, err := packet.NewPacket(
		packet.PACKET_TYPE_LINK,
		0x00,
		0x00,
		destPublicKey,
		l.linkID,
	)
	if err != nil {
		log.Printf("[DEBUG-3] Failed to create link request packet: %v", err)
		return err
	}

	log.Printf("[DEBUG-4] Sending link request packet with ID %x", l.linkID[:8])
	return l.transport.SendPacket(p)
}

func (l *Link) Identify(id *identity.Identity) error {
	if !l.IsActive() {
		return errors.New("link not active")
	}

	// Create identify packet
	p, err := packet.NewPacket(
		packet.PACKET_TYPE_IDENTIFY,
		0x00,
		0x00,
		l.destination.GetPublicKey(),
		id.GetPublicKey(),
	)
	if err != nil {
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

	log.Printf("[DEBUG-4] Sending encrypted packet of %d bytes", len(encrypted))
	l.lastOutbound = time.Now()
	l.lastDataSent = time.Now()

	return nil
}

func (l *Link) HandleInbound(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		log.Printf("[DEBUG-3] Dropping inbound packet: link not active (status: %d)", l.status)
		return errors.New("link not active")
	}

	log.Printf("[DEBUG-7] Received encrypted packet of %d bytes", len(data))

	// Decrypt data using session key
	decryptedData, err := l.decrypt(data)
	if err != nil {
		log.Printf("[DEBUG-3] Failed to decrypt packet: %v", err)
		return err
	}

	// Split message and HMAC
	if len(decryptedData) < sha256.Size {
		log.Printf("[DEBUG-3] Received data too short: %d bytes", len(decryptedData))
		return errors.New("received data too short")
	}

	message := decryptedData[:len(decryptedData)-sha256.Size]
	messageHMAC := decryptedData[len(decryptedData)-sha256.Size:]

	// Log packet details
	log.Printf("[DEBUG-7] Decrypted packet details:")
	log.Printf("[DEBUG-7] - Size: %d bytes", len(message))
	log.Printf("[DEBUG-7] - First 16 bytes: %x", message[:min(16, len(message))])
	if len(message) > 0 {
		log.Printf("[DEBUG-7] - Type: 0x%02x", message[0])
		switch message[0] {
		case packet.PacketData:
			log.Printf("[DEBUG-7] - Type: Data Packet")
		case packet.PacketAnnounce:
			log.Printf("[DEBUG-7] - Type: Announce Packet")
		case packet.PacketLinkRequest:
			log.Printf("[DEBUG-7] - Type: Link Request")
		case packet.PacketProof:
			log.Printf("[DEBUG-7] - Type: Proof Request")
		default:
			log.Printf("[DEBUG-7] - Type: Unknown (0x%02x)", message[0])
		}
	}

	// Verify HMAC
	if !l.destination.GetIdentity().ValidateHMAC(l.hmacKey, message, messageHMAC) {
		log.Printf("[DEBUG-3] Invalid HMAC for packet")
		return errors.New("invalid message authentication code")
	}

	l.lastInbound = time.Now()
	l.lastDataReceived = time.Now()

	if l.packetCallback != nil {
		l.packetCallback(message, nil)
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
	mode := cipher.NewCBCEncrypter(block, iv)
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

// Helper function for min of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
