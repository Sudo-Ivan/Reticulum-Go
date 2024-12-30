package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/destination"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/packet"
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

	// Add packet types
	PACKET_TYPE_DATA     = 0x00
	PACKET_TYPE_LINK     = 0x01
	PACKET_TYPE_IDENTIFY = 0x02
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

	// Add missing fields
	rssi                      float64
	snr                       float64
	q                         float64
	resourceCallback          func(interface{}) bool
	resourceStartedCallback   func(interface{})
	resourceConcludedCallback func(interface{})
	resourceStrategy          byte
}

func NewLink(dest *destination.Destination, transport *transport.Transport, establishedCallback func(*Link), closedCallback func(*Link)) *Link {
	return &Link{
		destination:        dest,
		status:            STATUS_PENDING,
		transport:         transport,
		establishedCallback: establishedCallback,
		closedCallback:     closedCallback,
		establishedAt:      time.Time{}, // Zero time until established
		lastInbound:        time.Time{},
		lastOutbound:       time.Time{},
		lastDataReceived:   time.Time{},
		lastDataSent:       time.Time{},
	}
}

func (l *Link) Establish() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_PENDING {
		return errors.New("link already established or failed")
	}

	destPublicKey := l.destination.GetPublicKey()
	if destPublicKey == nil {
		return errors.New("destination has no public key")
	}

	// Create link request packet
	p, err := packet.NewPacket(
		packet.PACKET_TYPE_LINK,
		0x00, // flags
		0x00, // hops
		destPublicKey,
		l.linkID,
	)
	if err != nil {
		return err
	}

	// Send through transport
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
		return errors.New("invalid identification data length")
	}

	pubKey := data[:ed25519.PublicKeySize]
	signature := data[ed25519.PublicKeySize:]

	remoteIdentity := identity.FromPublicKey(pubKey)
	if remoteIdentity == nil {
		return errors.New("invalid remote identity")
	}

	// Verify signature
	signData := append(l.linkID, pubKey...)
	if !remoteIdentity.Verify(signData, signature) {
		return errors.New("invalid signature")
	}

	l.remoteIdentity = remoteIdentity

	if l.identifiedCallback != nil {
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

func (l *Link) TrackPhyStats(rssi float64, snr float64, q float64) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.rssi = rssi
	l.snr = snr
	l.q = q
}

func (l *Link) GetRSSI() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.rssi
}

func (l *Link) GetSNR() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.snr
}

func (l *Link) GetQ() float64 {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
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
		return errors.New("link not active")
	}

	// Compute HMAC first
	messageHMAC := l.destination.GetIdentity().ComputeHMAC(l.hmacKey, data)

	// Combine data and HMAC
	authenticatedData := append(data, messageHMAC...)

	// Encrypt authenticated data using session key
	encryptedData, err := l.encrypt(authenticatedData)
	if err != nil {
		return err
	}

	l.lastOutbound = time.Now()
	l.lastDataSent = time.Now()

	if l.packetCallback != nil {
		l.packetCallback(encryptedData, nil)
	}

	return nil
}

func (l *Link) HandleInbound(data []byte) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.status != STATUS_ACTIVE {
		return errors.New("link not active")
	}

	// Decrypt data using session key
	decryptedData, err := l.decrypt(data)
	if err != nil {
		return err
	}

	// Split message and HMAC
	if len(decryptedData) < sha256.Size {
		return errors.New("received data too short")
	}

	message := decryptedData[:len(decryptedData)-sha256.Size]
	messageHMAC := decryptedData[len(decryptedData)-sha256.Size:]

	// Verify HMAC
	if !l.destination.GetIdentity().ValidateHMAC(l.hmacKey, message, messageHMAC) {
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

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (l *Link) decrypt(data []byte) ([]byte, error) {
	if l.sessionKey == nil {
		return nil, errors.New("no session key available")
	}

	block, err := aes.NewCipher(l.sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (l *Link) UpdatePhyStats(rssi float64, snr float64, q float64) {
	l.TrackPhyStats(rssi, snr, q)
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
