package destination

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
)

const (
	IN  = 0x01
	OUT = 0x02

	SINGLE = 0x00
	GROUP  = 0x01
	PLAIN  = 0x02

	PROVE_NONE = 0x00
	PROVE_ALL  = 0x01
	PROVE_APP  = 0x02

	ALLOW_NONE = 0x00
	ALLOW_ALL  = 0x01
	ALLOW_LIST = 0x02

	RATCHET_COUNT    = 512  // Default number of retained ratchet keys
	RATCHET_INTERVAL = 1800 // Minimum interval between ratchet rotations in seconds

	// Debug levels
	DEBUG_CRITICAL = 1 // Critical errors
	DEBUG_ERROR    = 2 // Non-critical errors
	DEBUG_INFO     = 3 // Important information
	DEBUG_VERBOSE  = 4 // Detailed information
	DEBUG_TRACE    = 5 // Very detailed tracing
	DEBUG_PACKETS  = 6 // Packet-level details
	DEBUG_ALL      = 7 // Everything
)

type PacketCallback = common.PacketCallback
type ProofRequestedCallback = common.ProofRequestedCallback
type LinkEstablishedCallback = common.LinkEstablishedCallback

type RequestHandler struct {
	Path              string
	ResponseGenerator func(path string, data []byte, requestID []byte, linkID []byte, remoteIdentity *identity.Identity, requestedAt int64) []byte
	AllowMode         byte
	AllowedList       [][]byte
}

type Destination struct {
	identity  *identity.Identity
	direction byte
	destType  byte
	appName   string
	aspects   []string
	hashValue []byte

	acceptsLinks  bool
	proofStrategy byte

	packetCallback PacketCallback
	proofCallback  ProofRequestedCallback
	linkCallback   LinkEstablishedCallback

	ratchetsEnabled bool
	ratchetPath     string
	ratchetCount    int
	ratchetInterval int
	enforceRatchets bool

	defaultAppData []byte
	mutex          sync.RWMutex

	requestHandlers map[string]*RequestHandler
}

func debugLog(level int, format string, v ...interface{}) {
	log.Printf("[DEBUG-%d] %s", level, fmt.Sprintf(format, v...))
}

func New(id *identity.Identity, direction byte, destType byte, appName string, aspects ...string) (*Destination, error) {
	debugLog(DEBUG_INFO, "Creating new destination: app=%s type=%d direction=%d", appName, destType, direction)

	if id == nil {
		debugLog(DEBUG_ERROR, "Cannot create destination: identity is nil")
		return nil, errors.New("identity cannot be nil")
	}

	d := &Destination{
		identity:        id,
		direction:       direction,
		destType:        destType,
		appName:         appName,
		aspects:         aspects,
		acceptsLinks:    false,
		proofStrategy:   PROVE_NONE,
		ratchetCount:    RATCHET_COUNT,
		ratchetInterval: RATCHET_INTERVAL,
		requestHandlers: make(map[string]*RequestHandler),
	}

	// Generate destination hash
	d.hashValue = d.calculateHash()
	debugLog(DEBUG_VERBOSE, "Created destination with hash: %x", d.hashValue)

	return d, nil
}

func (d *Destination) calculateHash() []byte {
	debugLog(DEBUG_TRACE, "Calculating hash for destination %s", d.ExpandName())

	nameHash := sha256.Sum256([]byte(d.ExpandName()))
	identityHash := sha256.Sum256(d.identity.GetPublicKey())

	debugLog(DEBUG_ALL, "Name hash: %x", nameHash)
	debugLog(DEBUG_ALL, "Identity hash: %x", identityHash)

	combined := append(nameHash[:], identityHash[:]...)
	finalHash := sha256.Sum256(combined)

	truncated := finalHash[:16]
	debugLog(DEBUG_VERBOSE, "Calculated destination hash: %x", truncated)

	return truncated
}

func (d *Destination) ExpandName() string {
	name := d.appName
	for _, aspect := range d.aspects {
		name += "." + aspect
	}
	return name
}

func (d *Destination) Announce(appData []byte) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.Printf("[DEBUG-4] Creating announce packet for destination %s", d.ExpandName())

	// If no specific appData provided, use default
	if appData == nil {
		log.Printf("[DEBUG-4] Using default app data for announce")
		appData = d.defaultAppData
	}

	// Create announce packet
	packet := make([]byte, 0, 256) // Pre-allocate reasonable size

	// Add packet type and header
	packet = append(packet, 0x01) // PACKET_TYPE_ANNOUNCE
	packet = append(packet, 0x00) // Initial hop count

	// Add destination hash (16 bytes)
	packet = append(packet, d.hashValue...)
	log.Printf("[DEBUG-4] Added destination hash %x to announce", d.hashValue[:8])

	// Add identity public key (32 bytes)
	pubKey := d.identity.GetPublicKey()
	packet = append(packet, pubKey...)
	log.Printf("[DEBUG-4] Added public key %x to announce", pubKey[:8])

	// Add app data with length prefix
	appDataLen := make([]byte, 2)
	binary.BigEndian.PutUint16(appDataLen, uint16(len(appData)))
	packet = append(packet, appDataLen...)
	packet = append(packet, appData...)
	log.Printf("[DEBUG-4] Added %d bytes of app data to announce", len(appData))

	// Add ratchet data if enabled
	if d.ratchetsEnabled {
		log.Printf("[DEBUG-4] Adding ratchet data to announce")
		ratchetKey := d.identity.GetCurrentRatchetKey()
		if ratchetKey == nil {
			log.Printf("[DEBUG-3] Failed to get current ratchet key")
			return errors.New("failed to get current ratchet key")
		}
		packet = append(packet, ratchetKey...)
		log.Printf("[DEBUG-4] Added ratchet key %x to announce", ratchetKey[:8])
	}

	// Sign the announce packet (64 bytes)
	signData := append(d.hashValue, appData...)
	if d.ratchetsEnabled {
		signData = append(signData, d.identity.GetCurrentRatchetKey()...)
	}
	signature := d.identity.Sign(signData)
	packet = append(packet, signature...)
	log.Printf("[DEBUG-4] Added signature to announce packet (total size: %d bytes)", len(packet))

	// Send announce packet through transport
	log.Printf("[DEBUG-4] Sending announce packet through transport layer")
	return transport.SendAnnounce(packet)
}

func (d *Destination) AcceptsLinks(accepts bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.acceptsLinks = accepts
}

func (d *Destination) SetLinkEstablishedCallback(callback common.LinkEstablishedCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.linkCallback = callback
}

func (d *Destination) SetPacketCallback(callback common.PacketCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.packetCallback = callback
}

func (d *Destination) SetProofRequestedCallback(callback common.ProofRequestedCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.proofCallback = callback
}

func (d *Destination) SetProofStrategy(strategy byte) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.proofStrategy = strategy
}

func (d *Destination) EnableRatchets(path string) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.ratchetsEnabled = true
	d.ratchetPath = path
	return true
}

func (d *Destination) EnforceRatchets() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.enforceRatchets = true
}

func (d *Destination) SetRetainedRatchets(count int) bool {
	if count < 1 {
		return false
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.ratchetCount = count
	return true
}

func (d *Destination) SetRatchetInterval(interval int) bool {
	if interval < 1 {
		return false
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.ratchetInterval = interval
	return true
}

func (d *Destination) SetDefaultAppData(data []byte) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.defaultAppData = data
}

func (d *Destination) ClearDefaultAppData() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.defaultAppData = nil
}

func (d *Destination) RegisterRequestHandler(path string, responseGen func(string, []byte, []byte, []byte, *identity.Identity, int64) []byte, allow byte, allowedList [][]byte) error {
	if path == "" {
		return errors.New("path cannot be empty")
	}

	if allow != ALLOW_NONE && allow != ALLOW_ALL && allow != ALLOW_LIST {
		return errors.New("invalid allow mode")
	}

	if allow == ALLOW_LIST && len(allowedList) == 0 {
		return errors.New("allowed list required for ALLOW_LIST mode")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.requestHandlers[path] = &RequestHandler{
		Path:              path,
		ResponseGenerator: responseGen,
		AllowMode:         allow,
		AllowedList:       allowedList,
	}

	return nil
}

func (d *Destination) DeregisterRequestHandler(path string) bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, exists := d.requestHandlers[path]; exists {
		delete(d.requestHandlers, path)
		return true
	}
	return false
}

func (d *Destination) Encrypt(plaintext []byte) ([]byte, error) {
	if d.destType == PLAIN {
		log.Printf("[DEBUG-4] Using plaintext transmission for PLAIN destination")
		return plaintext, nil
	}

	if d.identity == nil {
		log.Printf("[DEBUG-3] Cannot encrypt: no identity available")
		return nil, errors.New("no identity available for encryption")
	}

	log.Printf("[DEBUG-4] Encrypting %d bytes for destination type %d", len(plaintext), d.destType)

	switch d.destType {
	case SINGLE:
		recipientKey := d.identity.GetPublicKey()
		log.Printf("[DEBUG-4] Encrypting for single recipient with key %x", recipientKey[:8])
		return d.identity.Encrypt(plaintext, recipientKey)
	case GROUP:
		key := d.identity.GetCurrentRatchetKey()
		if key == nil {
			log.Printf("[DEBUG-3] Cannot encrypt: no ratchet key available")
			return nil, errors.New("no ratchet key available")
		}
		log.Printf("[DEBUG-4] Encrypting for group with ratchet key %x", key[:8])
		return d.identity.EncryptWithHMAC(plaintext, key)
	default:
		log.Printf("[DEBUG-3] Unsupported destination type %d for encryption", d.destType)
		return nil, errors.New("unsupported destination type for encryption")
	}
}

func (d *Destination) Decrypt(ciphertext []byte) ([]byte, error) {
	if d.destType == PLAIN {
		return ciphertext, nil
	}

	if d.identity == nil {
		return nil, errors.New("no identity available for decryption")
	}

	// Create empty ratchet receiver to get latest ratchet ID if available
	ratchetReceiver := &common.RatchetIDReceiver{}

	// Call Decrypt with full parameter list:
	// - ciphertext: the encrypted data
	// - ratchets: nil since we're not providing specific ratchets
	// - enforceRatchets: false to allow fallback to normal decryption
	// - ratchetIDReceiver: to receive the latest ratchet ID used
	return d.identity.Decrypt(ciphertext, nil, false, ratchetReceiver)
}

func (d *Destination) Sign(data []byte) ([]byte, error) {
	if d.identity == nil {
		return nil, errors.New("no identity available")
	}
	signature := d.identity.Sign(data)
	return signature, nil
}

func (d *Destination) GetPublicKey() []byte {
	if d.identity == nil {
		return nil
	}
	return d.identity.GetPublicKey()
}

func (d *Destination) GetIdentity() *identity.Identity {
	return d.identity
}

func (d *Destination) GetType() byte {
	return d.destType
}

func (d *Destination) GetHash() []byte {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	if d.hashValue == nil {
		d.mutex.RUnlock()
		d.mutex.Lock()
		defer d.mutex.Unlock()
		if d.hashValue == nil {
			d.hashValue = d.calculateHash()
		}
	}
	return d.hashValue
}
