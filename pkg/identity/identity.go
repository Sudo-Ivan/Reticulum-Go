package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
	"github.com/Sudo-Ivan/reticulum-go/pkg/cryptography"
	"github.com/Sudo-Ivan/reticulum-go/pkg/debug"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	CURVE                = "Curve25519"
	KEYSIZE              = 512 // Combined length of encryption key (256) and signing key (256)
	RATCHETSIZE          = 256
	RATCHET_EXPIRY       = 2592000 // 30 days in seconds
	TRUNCATED_HASHLENGTH = 128
	NAME_HASH_LENGTH     = 80

	// Token constants for Fernet-like spec
	TOKEN_OVERHEAD   = 16 // AES block size
	AES128_BLOCKSIZE = 16
	HASHLENGTH       = 256
	SIGLENGTH        = KEYSIZE

	RATCHET_ROTATION_INTERVAL = 1800 // Default 30 minutes in seconds
	MAX_RETAINED_RATCHETS     = 512  // Maximum number of retained ratchet keys
)

type Identity struct {
	privateKey      []byte
	publicKey       []byte
	signingSeed     []byte // 32-byte Ed25519 seed
	verificationKey ed25519.PublicKey
	hash            []byte
	hexHash         string
	appData         []byte

	ratchets      map[string][]byte
	ratchetExpiry map[string]int64
	mutex         *sync.RWMutex
}

var (
	knownDestinations  = make(map[string][]interface{})
	knownRatchets      = make(map[string][]byte)
	ratchetPersistLock sync.Mutex
)

func New() (*Identity, error) {
	i := &Identity{
		ratchets:      make(map[string][]byte),
		ratchetExpiry: make(map[string]int64),
		mutex:         &sync.RWMutex{},
	}

	// Generate keypairs using cryptography package
	privKey, pubKey, err := cryptography.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 keypair: %v", err)
	}
	i.privateKey = privKey
	i.publicKey = pubKey

	// Generate 32-byte Ed25519 seed
	var ed25519Seed [32]byte
	if _, err := io.ReadFull(rand.Reader, ed25519Seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 seed: %v", err)
	}

	// Derive Ed25519 keypair from seed
	privKeyEd := ed25519.NewKeyFromSeed(ed25519Seed[:])
	pubKeyEd := privKeyEd.Public().(ed25519.PublicKey)

	i.signingSeed = ed25519Seed[:]
	i.verificationKey = pubKeyEd

	return i, nil
}

func (i *Identity) GetPublicKey() []byte {
	// Combine encryption and signing public keys in correct order
	fullKey := make([]byte, 64)
	copy(fullKey[:32], i.publicKey)       // First 32 bytes: X25519 encryption key
	copy(fullKey[32:], i.verificationKey) // Last 32 bytes: Ed25519 verification key
	return fullKey
}

func (i *Identity) GetPrivateKey() []byte {
	return append(i.privateKey, i.signingSeed...)
}

func (i *Identity) Sign(data []byte) []byte {
	// Derive Ed25519 private key from seed
	privKey := ed25519.NewKeyFromSeed(i.signingSeed)
	return cryptography.Sign(privKey, data)
}

func (i *Identity) Verify(data []byte, signature []byte) bool {
	return cryptography.Verify(i.verificationKey, data, signature)
}

func (i *Identity) Encrypt(plaintext []byte, ratchet []byte) ([]byte, error) {
	// Generate ephemeral keypair
	ephemeralPrivKey, ephemeralPubKey, err := cryptography.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Use ratchet key if provided, otherwise use identity public key
	targetKey := i.publicKey
	if ratchet != nil {
		targetKey = ratchet
	}

	// Generate shared secret
	sharedSecret, err := cryptography.DeriveSharedSecret(ephemeralPrivKey, targetKey)
	if err != nil {
		return nil, err
	}

	// Derive encryption key
	key, err := cryptography.DeriveKey(sharedSecret, i.GetSalt(), i.GetContext(), 32)
	if err != nil {
		return nil, err
	}

	// Encrypt data
	ciphertext, err := cryptography.EncryptAES256CBC(key[:32], plaintext)
	if err != nil {
		return nil, err
	}

	// Calculate HMAC
	mac := cryptography.ComputeHMAC(key, append(ephemeralPubKey, ciphertext...))

	// Combine components
	token := make([]byte, 0, len(ephemeralPubKey)+len(ciphertext)+len(mac))
	token = append(token, ephemeralPubKey...)
	token = append(token, ciphertext...)
	token = append(token, mac...)

	return token, nil
}

func (i *Identity) Hash() []byte {
	hash := cryptography.Hash(i.GetPublicKey())
	return hash[:TRUNCATED_HASHLENGTH/8]
}

func TruncatedHash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	fullHash := h.Sum(nil)
	return fullHash[:TRUNCATED_HASHLENGTH/8]
}

func GetRandomHash() []byte {
	randomData := make([]byte, TRUNCATED_HASHLENGTH/8)
	_, err := rand.Read(randomData) // #nosec G104
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to read random data for hash", "error", err)
		return nil // Or handle the error appropriately
	}
	return TruncatedHash(randomData)
}

func Remember(packet []byte, destHash []byte, publicKey []byte, appData []byte) {
	hashStr := hex.EncodeToString(destHash)

	// Store destination data as [packet, destHash, identity, appData]
	id := FromPublicKey(publicKey)
	knownDestinations[hashStr] = []interface{}{
		packet,
		destHash,
		id,
		appData,
	}
}

func ValidateAnnounce(packet []byte, destHash []byte, publicKey []byte, signature []byte, appData []byte) bool {
	if len(publicKey) != KEYSIZE/8 {
		return false
	}

	// Split public key into encryption and verification keys
	announced := &Identity{
		publicKey:       publicKey[:KEYSIZE/16],
		verificationKey: publicKey[KEYSIZE/16:],
	}

	// Verify signature
	signedData := append(destHash, publicKey...)
	signedData = append(signedData, appData...)

	if !announced.Verify(signedData, signature) {
		return false
	}

	// Store in known destinations
	Remember(packet, destHash, publicKey, appData)
	return true
}

func FromPublicKey(publicKey []byte) *Identity {
	if len(publicKey) != KEYSIZE/8 {
		return nil
	}

	return &Identity{
		publicKey:       publicKey[:KEYSIZE/16],
		verificationKey: publicKey[KEYSIZE/16:],
		ratchets:        make(map[string][]byte),
		ratchetExpiry:   make(map[string]int64),
		mutex:           &sync.RWMutex{},
	}
}

func (i *Identity) Hex() string {
	return fmt.Sprintf("%x", i.Hash())
}

func (i *Identity) String() string {
	return i.Hex()
}

func Recall(hash []byte) (*Identity, error) {
	hashStr := hex.EncodeToString(hash)
	
	if data, exists := knownDestinations[hashStr]; exists {
		// data is [packet, destHash, identity, appData]
		if len(data) >= 3 {
			if id, ok := data[2].(*Identity); ok {
				return id, nil
			}
		}
	}
	
	return nil, fmt.Errorf("identity not found for hash %x", hash)
}

func (i *Identity) GenerateHMACKey() []byte {
	hmacKey := make([]byte, KEYSIZE/8)
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		return nil
	}
	return hmacKey
}

func (i *Identity) ComputeHMAC(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

func (i *Identity) ValidateHMAC(key, message, messageHMAC []byte) bool {
	expectedHMAC := i.ComputeHMAC(key, message)
	return hmac.Equal(messageHMAC, expectedHMAC)
}

func (i *Identity) GetCurrentRatchetKey() []byte {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	if len(i.ratchets) == 0 {
		// If no ratchets exist, generate one.
		// This should ideally be handled by an explicit setup process.
		debug.Log(debug.DEBUG_TRACE, "No ratchets found, generating a new one on-the-fly")
		// Temporarily unlock to call RotateRatchet, which locks internally.
		i.mutex.RUnlock()
		newRatchet, err := i.RotateRatchet()
		i.mutex.RLock()
		if err != nil {
			debug.Log(debug.DEBUG_CRITICAL, "Failed to generate initial ratchet key", "error", err)
			return nil
		}
		return newRatchet
	}

	// Return the most recently generated ratchet key
	var latestKey []byte
	var latestTime int64
	for id, expiry := range i.ratchetExpiry {
		if expiry > latestTime {
			latestTime = expiry
			latestKey = i.ratchets[id]
		}
	}

	if latestKey == nil {
		debug.Log(debug.DEBUG_ERROR, "Could not determine the latest ratchet key", "ratchet_count", len(i.ratchets))
	}

	return latestKey
}

func (i *Identity) Decrypt(ciphertextToken []byte, ratchets [][]byte, enforceRatchets bool, ratchetIDReceiver *common.RatchetIDReceiver) ([]byte, error) {
	if i.privateKey == nil {
		debug.Log(debug.DEBUG_CRITICAL, "Decryption failed: identity has no private key")
		return nil, errors.New("decryption failed because identity does not hold a private key")
	}

	debug.Log(debug.DEBUG_ALL, "Starting decryption for identity", "hash", i.GetHexHash())
	if len(ratchets) > 0 {
		debug.Log(debug.DEBUG_ALL, "Attempting decryption with ratchets", "count", len(ratchets))
	}

	if len(ciphertextToken) <= KEYSIZE/8/2 {
		return nil, errors.New("decryption failed because the token size was invalid")
	}

	// Extract components: ephemeralPubKey(32) + ciphertext + mac(32)
	if len(ciphertextToken) < 32+32+32 { // minimum sizes
		return nil, errors.New("token too short")
	}

	peerPubBytes := ciphertextToken[:32]
	ciphertext := ciphertextToken[32 : len(ciphertextToken)-32]
	mac := ciphertextToken[len(ciphertextToken)-32:]

	// Try decryption with ratchets first if provided
	if len(ratchets) > 0 {
		for _, ratchet := range ratchets {
			if decrypted, ratchetID, err := i.tryRatchetDecryption(peerPubBytes, ciphertext, ratchet); err == nil {
				if ratchetIDReceiver != nil {
					ratchetIDReceiver.LatestRatchetID = ratchetID
				}
				return decrypted, nil
			}
		}

		if enforceRatchets {
			if ratchetIDReceiver != nil {
				ratchetIDReceiver.LatestRatchetID = nil
			}
			return nil, errors.New("decryption with ratchet enforcement failed")
		}
	}

	// Try normal decryption if ratchet decryption failed or wasn't requested
	sharedKey, err := curve25519.X25519(i.privateKey, peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %v", err)
	}

	// Derive key using HKDF
	hkdfReader := hkdf.New(sha256.New, sharedKey, i.GetSalt(), i.GetContext())
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	// Validate HMAC
	if !cryptography.ValidateHMAC(derivedKey, append(peerPubBytes, ciphertext...), mac) {
		return nil, errors.New("invalid HMAC")
	}

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Extract IV and decrypt
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	actualCiphertext := ciphertext[aes.BlockSize:]

	if len(actualCiphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(actualCiphertext))
	mode.CryptBlocks(plaintext, actualCiphertext)

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

	if ratchetIDReceiver != nil {
		ratchetIDReceiver.LatestRatchetID = nil
	}

	debug.Log(debug.DEBUG_ALL, "Decryption completed successfully")
	return plaintext[:len(plaintext)-padding], nil
}

// Helper function to attempt decryption using a ratchet
func (i *Identity) tryRatchetDecryption(peerPubBytes, ciphertext, ratchet []byte) (plaintext, ratchetID []byte, err error) {
	// Convert ratchet to private key
	ratchetPriv := ratchet

	// Get ratchet ID
	ratchetPubBytes, err := curve25519.X25519(ratchetPriv, cryptography.GetBasepoint())
	if err != nil {
		debug.Log(debug.DEBUG_ALL, "Failed to generate ratchet public key", "error", err)
		return nil, nil, err
	}
	ratchetID = i.GetRatchetID(ratchetPubBytes)

	sharedSecret, err := cryptography.DeriveSharedSecret(ratchet, peerPubBytes)
	if err != nil {
		return nil, nil, err
	}

	key, err := cryptography.DeriveKey(sharedSecret, i.GetSalt(), i.GetContext(), 32)
	if err != nil {
		return nil, nil, err
	}

	plaintext, err = cryptography.DecryptAES256CBC(key, ciphertext)
	if err != nil {
		return nil, nil, err
	}

	return plaintext, ratchetID, nil
}

func (i *Identity) EncryptWithHMAC(plaintext []byte, key []byte) ([]byte, error) {
	ciphertext, err := cryptography.EncryptAES256CBC(key, plaintext)
	if err != nil {
		return nil, err
	}

	mac := cryptography.ComputeHMAC(key, ciphertext)
	return append(ciphertext, mac...), nil
}

func (i *Identity) DecryptWithHMAC(data []byte, key []byte) ([]byte, error) {
	if len(data) < cryptography.SHA256Size {
		return nil, errors.New("data too short")
	}

	macStart := len(data) - cryptography.SHA256Size
	ciphertext := data[:macStart]
	messageMAC := data[macStart:]

	if !cryptography.ValidateHMAC(key, ciphertext, messageMAC) {
		return nil, errors.New("invalid HMAC")
	}

	return cryptography.DecryptAES256CBC(key, ciphertext)
}

func (i *Identity) ToFile(path string) error {
	debug.Log(debug.DEBUG_ALL, "Saving identity to file", "hash", i.GetHexHash(), "path", path)

	if i.privateKey == nil || i.signingSeed == nil {
		return errors.New("cannot save identity without private keys")
	}

	// Store private keys as raw bytes
	// Format: [X25519 PrivKey (32 bytes)][Ed25519 PrivKey (32 bytes)]
	// Total: 64 bytes
	privateKeyBytes := make([]byte, 64)
	copy(privateKeyBytes[:32], i.privateKey)
	copy(privateKeyBytes[32:], i.signingSeed)

	// Write raw bytes to file
	file, err := os.Create(path) // #nosec G304
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to create identity file", "error", err)
		return err
	}
	defer file.Close()

	if _, err := file.Write(privateKeyBytes); err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to write identity data", "error", err)
		return err
	}

	debug.Log(debug.DEBUG_ALL, "Identity saved successfully", "bytes", len(privateKeyBytes))
	return nil
}

func (i *Identity) saveRatchets(path string) error {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	if len(i.ratchets) == 0 {
		return nil // Nothing to save
	}

	debug.Log(debug.DEBUG_PACKETS, "Saving ratchets", "count", len(i.ratchets), "path", path)
	
	// Convert ratchets to list format for msgpack
	ratchetList := make([][]byte, 0, len(i.ratchets))
	for _, ratchet := range i.ratchets {
		ratchetList = append(ratchetList, ratchet)
	}

	// Pack ratchets using msgpack
	packedRatchets, err := msgpack.Marshal(ratchetList)
	if err != nil {
		return fmt.Errorf("failed to pack ratchets: %w", err)
	}

	// Sign the packed ratchets
	signature := i.Sign(packedRatchets)

	// Create structure: {"signature": ..., "ratchets": ...}
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
	tempPath := path + ".tmp"
	file, err := os.Create(tempPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to create temp ratchet file: %w", err)
	}

	if _, err := file.Write(finalData); err != nil {
		// #nosec G104 - Error already being handled, cleanup errors are non-critical
		file.Close()
		// #nosec G104 - Error already being handled, cleanup errors are non-critical
		os.Remove(tempPath)
		return fmt.Errorf("failed to write ratchet data: %w", err)
	}
	// #nosec G104 - File is being closed after successful write, error is non-critical
	file.Close()

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		// #nosec G104 - Error already being handled, cleanup errors are non-critical
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename ratchet file: %w", err)
	}

	debug.Log(debug.DEBUG_PACKETS, "Ratchets saved successfully")
	return nil
}

func RecallIdentity(path string) (*Identity, error) {
	debug.Log(debug.DEBUG_ALL, "Attempting to recall identity", "path", path)

	file, err := os.Open(path) // #nosec G304
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to open identity file", "error", err)
		return nil, err
	}
	defer file.Close()

	// Read raw bytes
	// Format: [X25519 PrivKey (32 bytes)][Ed25519 PrivKey (32 bytes)]
	privateKeyBytes := make([]byte, 64)
	n, err := io.ReadFull(file, privateKeyBytes)
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to read identity data", "error", err)
		return nil, err
	}
	if n != 64 {
		return nil, fmt.Errorf("invalid identity file: expected 64 bytes, got %d", n)
	}

	// Extract keys
	x25519PrivKey := privateKeyBytes[:32]
	ed25519Seed := privateKeyBytes[32:]

	// Derive public keys
	x25519PubKey, err := curve25519.X25519(x25519PrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %v", err)
	}

	ed25519PrivKey := ed25519.NewKeyFromSeed(ed25519Seed)
	ed25519PubKey := ed25519PrivKey.Public().(ed25519.PublicKey)

	id := &Identity{
		privateKey:      x25519PrivKey,
		publicKey:       x25519PubKey,
		signingSeed:     ed25519Seed,
		verificationKey: ed25519PubKey,
		ratchets:        make(map[string][]byte),
		ratchetExpiry:   make(map[string]int64),
		mutex:           &sync.RWMutex{},
	}

	// Generate hash
	combinedPub := make([]byte, KEYSIZE/8)
	copy(combinedPub[:KEYSIZE/16], id.publicKey)
	copy(combinedPub[KEYSIZE/16:], id.verificationKey)
	hash := sha256.Sum256(combinedPub)
	id.hash = hash[:]

	debug.Log(debug.DEBUG_ALL, "Successfully recalled identity", "hash", id.GetHexHash())
	return id, nil
}

func (i *Identity) loadRatchets(path string) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	file, err := os.Open(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			debug.Log(debug.DEBUG_PACKETS, "No ratchet file found, skipping", "path", path)
			return nil
		}
		return fmt.Errorf("failed to open ratchet file: %w", err)
	}
	defer file.Close()

	// Read all data
	fileData, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read ratchet file: %w", err)
	}

	// Unpack outer structure: {"signature": ..., "ratchets": ...}
	var persistedData map[string][]byte
	if err := msgpack.Unmarshal(fileData, &persistedData); err != nil {
		return fmt.Errorf("failed to unpack ratchet data: %w", err)
	}

	signature, hasSignature := persistedData["signature"]
	packedRatchets, hasRatchets := persistedData["ratchets"]
	
	if !hasSignature || !hasRatchets {
		return fmt.Errorf("invalid ratchet file format: missing signature or ratchets")
	}

	// Verify signature
	if !i.Verify(packedRatchets, signature) {
		return fmt.Errorf("invalid ratchet file signature")
	}

	// Unpack ratchet list
	var ratchetList [][]byte
	if err := msgpack.Unmarshal(packedRatchets, &ratchetList); err != nil {
		return fmt.Errorf("failed to unpack ratchet list: %w", err)
	}

	// Store ratchets with generated IDs
	now := time.Now().Unix()
	for _, ratchet := range ratchetList {
		// Generate ratchet public key to create ID
		ratchetPub, err := curve25519.X25519(ratchet, curve25519.Basepoint)
		if err != nil {
			debug.Log(debug.DEBUG_ERROR, "Failed to generate ratchet public key", "error", err)
			continue
		}
		ratchetID := i.GetRatchetID(ratchetPub)
		i.ratchets[string(ratchetID)] = ratchet
		i.ratchetExpiry[string(ratchetID)] = now + RATCHET_EXPIRY
	}

	debug.Log(debug.DEBUG_PACKETS, "Loaded ratchets", "count", len(i.ratchets), "path", path)
	return nil
}

func HashFromString(hash string) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("invalid hash length: expected 32, got %d", len(hash))
	}

	return hex.DecodeString(hash)
}

func (i *Identity) GetSalt() []byte {
	return i.hash
}

func (i *Identity) GetContext() []byte {
	return nil
}

func (i *Identity) GetRatchetID(ratchetPubBytes []byte) []byte {
	hash := cryptography.Hash(ratchetPubBytes)
	return hash[:NAME_HASH_LENGTH/8]
}

func GetKnownDestination(hash string) ([]interface{}, bool) {
	if data, exists := knownDestinations[hash]; exists {
		return data, true
	}
	return nil, false
}

func (i *Identity) GetHexHash() string {
	if i.hexHash == "" {
		i.hexHash = hex.EncodeToString(i.Hash())
	}
	return i.hexHash
}

func (i *Identity) GetRatchetKey(id string) ([]byte, bool) {
	ratchetPersistLock.Lock()
	defer ratchetPersistLock.Unlock()

	key, exists := knownRatchets[id]
	return key, exists
}

func (i *Identity) SetRatchetKey(id string, key []byte) {
	ratchetPersistLock.Lock()
	defer ratchetPersistLock.Unlock()

	knownRatchets[id] = key
}

// NewIdentity creates a new Identity instance with fresh keys
func NewIdentity() (*Identity, error) {
	// Generate 32-byte Ed25519 seed
	var ed25519Seed [32]byte
	if _, err := io.ReadFull(rand.Reader, ed25519Seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 seed: %v", err)
	}

	// Derive Ed25519 keypair from seed
	privKey := ed25519.NewKeyFromSeed(ed25519Seed[:])
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Generate X25519 encryption keypair
	var encPrivKey [32]byte
	if _, err := io.ReadFull(rand.Reader, encPrivKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %v", err)
	}

	encPubKey, err := curve25519.X25519(encPrivKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 public key: %v", err)
	}

	i := &Identity{
		privateKey:      encPrivKey[:],
		publicKey:       encPubKey,
		signingSeed:     ed25519Seed[:],
		verificationKey: pubKey,
		ratchets:        make(map[string][]byte),
		ratchetExpiry:   make(map[string]int64),
		mutex:           &sync.RWMutex{},
	}

	// Generate hash
	combinedPub := make([]byte, KEYSIZE/8)
	copy(combinedPub[:KEYSIZE/16], i.publicKey)
	copy(combinedPub[KEYSIZE/16:], i.verificationKey)
	hash := sha256.Sum256(combinedPub)
	i.hash = hash[:]

	return i, nil
}

func (i *Identity) RotateRatchet() ([]byte, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	debug.Log(debug.DEBUG_ALL, "Rotating ratchet for identity", "hash", i.GetHexHash())

	// Generate new ratchet key
	newRatchet := make([]byte, RATCHETSIZE/8)
	if _, err := io.ReadFull(rand.Reader, newRatchet); err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to generate new ratchet", "error", err)
		return nil, err
	}

	// Get public key for ratchet ID
	ratchetPub, err := curve25519.X25519(newRatchet, curve25519.Basepoint)
	if err != nil {
		debug.Log(debug.DEBUG_CRITICAL, "Failed to generate ratchet public key", "error", err)
		return nil, err
	}

	ratchetID := i.GetRatchetID(ratchetPub)
	expiry := time.Now().Unix() + RATCHET_EXPIRY

	// Store new ratchet
	i.ratchets[string(ratchetID)] = newRatchet
	i.ratchetExpiry[string(ratchetID)] = expiry

	debug.Log(debug.DEBUG_ALL, "New ratchet generated", "id", fmt.Sprintf("%x", ratchetID), "expiry", expiry)

	// Cleanup old ratchets if we exceed max retained
	if len(i.ratchets) > MAX_RETAINED_RATCHETS {
		var oldestID string
		oldestTime := time.Now().Unix()

		for id, exp := range i.ratchetExpiry {
			if exp < oldestTime {
				oldestTime = exp
				oldestID = id
			}
		}

		delete(i.ratchets, oldestID)
		delete(i.ratchetExpiry, oldestID)
		debug.Log(debug.DEBUG_ALL, "Cleaned up oldest ratchet", "id", fmt.Sprintf("%x", []byte(oldestID)))
	}

	debug.Log(debug.DEBUG_ALL, "Current number of active ratchets", "count", len(i.ratchets))
	return newRatchet, nil
}

func (i *Identity) GetRatchets() [][]byte {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	debug.Log(debug.DEBUG_ALL, "Getting ratchets for identity", "hash", i.GetHexHash())

	ratchets := make([][]byte, 0, len(i.ratchets))
	now := time.Now().Unix()
	expired := 0

	// Return only non-expired ratchets
	for id, expiry := range i.ratchetExpiry {
		if expiry > now {
			ratchets = append(ratchets, i.ratchets[id])
		} else {
			// Clean up expired ratchets
			delete(i.ratchets, id)
			delete(i.ratchetExpiry, id)
			expired++
		}
	}

	debug.Log(debug.DEBUG_ALL, "Retrieved active ratchets", "active", len(ratchets), "expired", expired)
	return ratchets
}

func (i *Identity) CleanupExpiredRatchets() {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	debug.Log(debug.DEBUG_ALL, "Starting ratchet cleanup for identity", "hash", i.GetHexHash())

	now := time.Now().Unix()
	cleaned := 0
	for id, expiry := range i.ratchetExpiry {
		if expiry <= now {
			delete(i.ratchets, id)
			delete(i.ratchetExpiry, id)
			cleaned++
		}
	}

	debug.Log(debug.DEBUG_ALL, "Cleaned up expired ratchets", "cleaned", cleaned, "remaining", len(i.ratchets))
}

// ValidateAnnounce validates an announce packet's signature
func (i *Identity) ValidateAnnounce(data []byte, destHash []byte, appData []byte) bool {
	if i == nil || len(data) < ed25519.SignatureSize {
		return false
	}

	signatureStart := len(data) - ed25519.SignatureSize
	signature := data[signatureStart:]
	signedData := append(destHash, i.GetPublicKey()...)
	signedData = append(signedData, appData...)

	return ed25519.Verify(i.verificationKey, signedData, signature)
}

// GetNameHash returns a 10-byte hash derived from the identity's public key
func (i *Identity) GetNameHash() []byte {
	if i == nil || i.publicKey == nil {
		return nil
	}

	// Generate hash from combined public key
	h := sha256.New()
	h.Write(i.GetPublicKey())
	fullHash := h.Sum(nil)

	// Return first 10 bytes (NAME_HASH_LENGTH/8)
	return fullHash[:NAME_HASH_LENGTH/8]
}

// GetEncryptionKey returns the X25519 public key used for encryption
func (i *Identity) GetEncryptionKey() []byte {
	return i.publicKey
}

// GetSigningKey returns the Ed25519 public key used for signing
func (i *Identity) GetSigningKey() []byte {
	return i.verificationKey
}
