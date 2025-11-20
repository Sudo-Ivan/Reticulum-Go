package destination

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/announce"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/Sudo-Ivan/reticulum-go/pkg/identity"
	"github.com/Sudo-Ivan/reticulum-go/pkg/transport"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
)

const (
	// Destination direction types
	// The IN bit specifies that the destination can receive traffic.
	// The OUT bit specifies that the destination can send traffic.
	// A destination can be both IN and OUT.
	IN  = 0x01
	OUT = 0x02

	// Destination types
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
	transport *transport.Transport

	acceptsLinks  bool
	proofStrategy byte

	packetCallback PacketCallback
	proofCallback  ProofRequestedCallback
	linkCallback   LinkEstablishedCallback

	ratchetsEnabled    bool
	ratchetPath        string
	ratchetCount       int
	ratchetInterval    int
	enforceRatchets    bool
	latestRatchetTime  time.Time
	latestRatchetID    []byte
	ratchets           [][]byte
	ratchetFileLock    sync.Mutex

	defaultAppData []byte
	mutex          sync.RWMutex

	requestHandlers map[string]*RequestHandler
}

func New(id *identity.Identity, direction byte, destType byte, appName string, transport *transport.Transport, aspects ...string) (*Destination, error) {
	debug.Log(debug.DEBUG_INFO, "Creating new destination", "app", appName, "type", destType, "direction", direction)

	if id == nil {
		debug.Log(debug.DEBUG_ERROR, "Cannot create destination: identity is nil")
		return nil, errors.New("identity cannot be nil")
	}

	d := &Destination{
		identity:        id,
		direction:       direction,
		destType:        destType,
		appName:         appName,
		aspects:         aspects,
		transport:       transport,
		acceptsLinks:    false,
		proofStrategy:   PROVE_NONE,
		ratchetCount:    RATCHET_COUNT,
		ratchetInterval: RATCHET_INTERVAL,
		requestHandlers: make(map[string]*RequestHandler),
	}

	// Generate destination hash
	d.hashValue = d.calculateHash()
	debug.Log(debug.DEBUG_VERBOSE, "Created destination with hash", "hash", fmt.Sprintf("%x", d.hashValue))

	return d, nil
}

// FromHash creates a destination from a known hash (e.g., from an announce).
// This is used by clients to create destination objects for servers they've discovered.
func FromHash(hash []byte, id *identity.Identity, destType byte, transport *transport.Transport) (*Destination, error) {
	debug.Log(debug.DEBUG_INFO, "Creating destination from hash", "hash", fmt.Sprintf("%x", hash))

	if id == nil {
		debug.Log(debug.DEBUG_ERROR, "Cannot create destination: identity is nil")
		return nil, errors.New("identity cannot be nil")
	}

	d := &Destination{
		identity:        id,
		direction:       OUT,
		destType:        destType,
		hashValue:       hash,
		transport:       transport,
		acceptsLinks:    false,
		proofStrategy:   PROVE_NONE,
		ratchetCount:    RATCHET_COUNT,
		ratchetInterval: RATCHET_INTERVAL,
		requestHandlers: make(map[string]*RequestHandler),
	}

	debug.Log(debug.DEBUG_VERBOSE, "Created destination from hash", "hash", fmt.Sprintf("%x", hash))
	return d, nil
}

func (d *Destination) calculateHash() []byte {
	debug.Log(debug.DEBUG_TRACE, "Calculating hash for destination", "name", d.ExpandName())

	// destination_hash = SHA256(name_hash_10bytes + identity_hash_16bytes)[:16]
	// Identity hash is the truncated hash of the public key (16 bytes)
	identityHash := identity.TruncatedHash(d.identity.GetPublicKey())
	
	// Name hash is the FULL 32-byte SHA256, then we take first 10 bytes for concatenation
	nameHashFull := sha256.Sum256([]byte(d.ExpandName()))
	nameHash10 := nameHashFull[:10]  // Only use 10 bytes

	debug.Log(debug.DEBUG_ALL, "Identity hash", "hash", fmt.Sprintf("%x", identityHash))
	debug.Log(debug.DEBUG_ALL, "Name hash (10 bytes)", "hash", fmt.Sprintf("%x", nameHash10))

	// Concatenate name_hash (10 bytes) + identity_hash (16 bytes) = 26 bytes
	combined := append(nameHash10, identityHash...)
	
	// Then hash again and truncate to 16 bytes
	finalHashFull := sha256.Sum256(combined)
	finalHash := finalHashFull[:16]

	debug.Log(debug.DEBUG_VERBOSE, "Calculated destination hash", "hash", fmt.Sprintf("%x", finalHash))

	return finalHash
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

	debug.Log(debug.DEBUG_VERBOSE, "Announcing destination", "name", d.ExpandName())

	if appData == nil {
		appData = d.defaultAppData
	}

	// Create announce packet using announce package
	// Pass the destination hash, name, and app data
	announce, err := announce.New(d.identity, d.hashValue, d.ExpandName(), appData, false, d.transport.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to create announce: %w", err)
	}

	packet := announce.GetPacket()
	if packet == nil {
		return errors.New("failed to create announce packet")
	}

	// Send announce packet to all interfaces
	debug.Log(debug.DEBUG_VERBOSE, "Sending announce packet to all interfaces")
	if d.transport == nil {
		return errors.New("transport not initialized")
	}

	interfaces := d.transport.GetInterfaces()
	debug.Log(debug.DEBUG_ALL, "Got interfaces from transport", "count", len(interfaces))

	var lastErr error
	for name, iface := range interfaces {
		debug.Log(debug.DEBUG_ALL, "Checking interface", "name", name, "enabled", iface.IsEnabled(), "online", iface.IsOnline())
		if iface.IsEnabled() && iface.IsOnline() {
			debug.Log(debug.DEBUG_ALL, "Sending announce to interface", "name", name, "bytes", len(packet))
			if err := iface.Send(packet, ""); err != nil {
				debug.Log(debug.DEBUG_ERROR, "Failed to send announce on interface", "name", name, "error", err)
				lastErr = err
			} else {
				debug.Log(debug.DEBUG_ALL, "Successfully sent announce to interface", "name", name)
			}
		} else {
			debug.Log(debug.DEBUG_ALL, "Skipping interface", "name", name, "reason", "not enabled or not online")
		}
	}

	return lastErr
}

func (d *Destination) AcceptsLinks(accepts bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.acceptsLinks = accepts
	
	// Register with transport if accepting links
	if accepts && d.transport != nil {
		d.transport.RegisterDestination(d.hashValue, d)
		debug.Log(debug.DEBUG_VERBOSE, "Destination registered with transport for link requests", "hash", fmt.Sprintf("%x", d.hashValue))
	}
}

func (d *Destination) SetLinkEstablishedCallback(callback common.LinkEstablishedCallback) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.linkCallback = callback
}

func (d *Destination) GetLinkCallback() common.LinkEstablishedCallback {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.linkCallback
}

func (d *Destination) HandleIncomingLinkRequest(linkID []byte, transport interface{}, networkIface common.NetworkInterface) error {
	debug.Log(debug.DEBUG_INFO, "Handling incoming link request for destination", "hash", fmt.Sprintf("%x", d.GetHash()))
	
	// Import link package here to avoid circular dependency at package level
	// We'll use dynamic import by having the caller create the link
	// For now, just call the callback with a placeholder
	
	if d.linkCallback != nil {
		debug.Log(debug.DEBUG_INFO, "Calling link established callback")
		// Pass linkID as the link object for now
		// The callback will need to handle creating the actual link
		d.linkCallback(linkID)
	} else {
		debug.Log(debug.DEBUG_VERBOSE, "No link callback set")
	}
	
	return nil
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

	if path == "" {
		debug.Log(debug.DEBUG_ERROR, "No ratchet file path specified")
		return false
	}

	d.ratchetsEnabled = true
	d.ratchetPath = path
	d.latestRatchetTime = time.Time{} // Zero time to force rotation

	// Load or initialize ratchets
	if err := d.reloadRatchets(); err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to load ratchets", "error", err)
		// Initialize empty ratchet list
		d.ratchets = make([][]byte, 0)
		if err := d.persistRatchets(); err != nil {
			debug.Log(debug.DEBUG_ERROR, "Failed to create initial ratchet file", "error", err)
			return false
		}
	}

	debug.Log(debug.DEBUG_INFO, "Ratchets enabled", "path", path)
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
		debug.Log(debug.DEBUG_VERBOSE, "Using plaintext transmission for PLAIN destination")
		return plaintext, nil
	}

	if d.identity == nil {
		debug.Log(debug.DEBUG_INFO, "Cannot encrypt: no identity available")
		return nil, errors.New("no identity available for encryption")
	}

	debug.Log(debug.DEBUG_VERBOSE, "Encrypting bytes for destination", "bytes", len(plaintext), "destType", d.destType)

	switch d.destType {
	case SINGLE:
		recipientKey := d.identity.GetPublicKey()
		debug.Log(debug.DEBUG_VERBOSE, "Encrypting for single recipient", "key", fmt.Sprintf("%x", recipientKey[:8]))
		return d.identity.Encrypt(plaintext, recipientKey)
	case GROUP:
		key := d.identity.GetCurrentRatchetKey()
		if key == nil {
			debug.Log(debug.DEBUG_INFO, "Cannot encrypt: no ratchet key available")
			return nil, errors.New("no ratchet key available")
		}
		debug.Log(debug.DEBUG_VERBOSE, "Encrypting for group with ratchet key", "key", fmt.Sprintf("%x", key[:8]))
		return d.identity.EncryptWithHMAC(plaintext, key)
	default:
		debug.Log(debug.DEBUG_INFO, "Unsupported destination type for encryption", "destType", d.destType)
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

func (d *Destination) persistRatchets() error {
	d.ratchetFileLock.Lock()
	defer d.ratchetFileLock.Unlock()

	if !d.ratchetsEnabled || d.ratchetPath == "" {
		return errors.New("ratchets not enabled or no path specified")
	}

	debug.Log(debug.DEBUG_PACKETS, "Persisting ratchets", "count", len(d.ratchets), "path", d.ratchetPath)

	// Pack ratchets using msgpack
	packedRatchets, err := msgpack.Marshal(d.ratchets)
	if err != nil {
		return fmt.Errorf("failed to pack ratchets: %w", err)
	}

	// Sign the packed ratchets
	signature, err := d.Sign(packedRatchets)
	if err != nil {
		return fmt.Errorf("failed to sign ratchets: %w", err)
	}

	// Create structure
	persistedData := map[string][]byte{
		"signature": signature,
		"ratchets":  packedRatchets,
	}

	// Pack the entire structure
	finalData, err := msgpack.Marshal(persistedData)
	if err != nil {
		return fmt.Errorf("failed to pack ratchet data: %w", err)
	}

	// Write to temporary file first, then rename (atomic operation)
	tempPath := d.ratchetPath + ".tmp"
	file, err := os.Create(tempPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to create temp ratchet file: %w", err)
	}

	if _, err := file.Write(finalData); err != nil {
		file.Close()
		os.Remove(tempPath)
		return fmt.Errorf("failed to write ratchet data: %w", err)
	}
	file.Close()

	// Remove old file if exists
	if _, err := os.Stat(d.ratchetPath); err == nil {
		os.Remove(d.ratchetPath)
	}

	// Atomic rename
	if err := os.Rename(tempPath, d.ratchetPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename ratchet file: %w", err)
	}

	debug.Log(debug.DEBUG_PACKETS, "Ratchets persisted successfully")
	return nil
}

func (d *Destination) reloadRatchets() error {
	d.ratchetFileLock.Lock()
	defer d.ratchetFileLock.Unlock()

	if _, err := os.Stat(d.ratchetPath); os.IsNotExist(err) {
		debug.Log(debug.DEBUG_INFO, "No existing ratchet data found, initializing new ratchet file")
		d.ratchets = make([][]byte, 0)
		return nil
	}

	file, err := os.Open(d.ratchetPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to open ratchet file: %w", err)
	}
	defer file.Close()

	// Read all data
	fileData, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read ratchet file: %w", err)
	}

	// Unpack outer structure
	var persistedData map[string][]byte
	if err := msgpack.Unmarshal(fileData, &persistedData); err != nil {
		return fmt.Errorf("failed to unpack ratchet data: %w", err)
	}

	signature, hasSignature := persistedData["signature"]
	packedRatchets, hasRatchets := persistedData["ratchets"]

	if !hasSignature || !hasRatchets {
		return fmt.Errorf("invalid ratchet file format")
	}

	// Verify signature
	if !d.identity.Verify(packedRatchets, signature) {
		return fmt.Errorf("invalid ratchet file signature")
	}

	// Unpack ratchet list
	if err := msgpack.Unmarshal(packedRatchets, &d.ratchets); err != nil {
		return fmt.Errorf("failed to unpack ratchet list: %w", err)
	}

	debug.Log(debug.DEBUG_INFO, "Ratchets reloaded successfully", "count", len(d.ratchets))
	return nil
}

func (d *Destination) RotateRatchets() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.ratchetsEnabled {
		return errors.New("ratchets not enabled")
	}

	now := time.Now()
	if !d.latestRatchetTime.IsZero() && now.Before(d.latestRatchetTime.Add(time.Duration(d.ratchetInterval)*time.Second)) {
		debug.Log(debug.DEBUG_TRACE, "Ratchet rotation interval not reached")
		return nil
	}

	debug.Log(debug.DEBUG_INFO, "Rotating ratchets", "destination", d.ExpandName())

	// Generate new ratchet key (32 bytes for X25519 private key)
	newRatchet := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newRatchet); err != nil {
		return fmt.Errorf("failed to generate new ratchet: %w", err)
	}

	// Insert at beginning (most recent first)
	d.ratchets = append([][]byte{newRatchet}, d.ratchets...)
	d.latestRatchetTime = now

	// Get ratchet public key for ID
	ratchetPub, err := curve25519.X25519(newRatchet, curve25519.Basepoint)
	if err == nil {
		d.latestRatchetID = identity.TruncatedHash(ratchetPub)[:identity.NAME_HASH_LENGTH/8]
	}

	// Clean old ratchets
	d.cleanRatchets()

	// Persist to disk
	if err := d.persistRatchets(); err != nil {
		debug.Log(debug.DEBUG_ERROR, "Failed to persist ratchets after rotation", "error", err)
		return err
	}

	debug.Log(debug.DEBUG_INFO, "Ratchet rotation completed", "total_ratchets", len(d.ratchets))
	return nil
}

func (d *Destination) cleanRatchets() {
	if len(d.ratchets) > d.ratchetCount {
		debug.Log(debug.DEBUG_TRACE, "Cleaning old ratchets", "before", len(d.ratchets), "keeping", d.ratchetCount)
		d.ratchets = d.ratchets[:d.ratchetCount]
	}
}

func (d *Destination) GetRatchets() [][]byte {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if !d.ratchetsEnabled {
		return nil
	}

	// Return copy to prevent external modification
	ratchetsCopy := make([][]byte, len(d.ratchets))
	copy(ratchetsCopy, d.ratchets)
	return ratchetsCopy
}
