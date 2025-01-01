package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"encoding/hex"

	"log"

	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
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
	signingKey      ed25519.PrivateKey
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

func encryptAESCBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := make([]byte, len(plaintext)+padding)
	copy(padtext, plaintext)
	for i := len(plaintext); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padtext))
	mode.CryptBlocks(ciphertext, padtext)

	// Prepend IV to ciphertext
	return append(iv, ciphertext...), nil
}

func decryptAESCBC(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	padding := int(plaintext[len(plaintext)-1])
	return plaintext[:len(plaintext)-padding], nil
}

func New() (*Identity, error) {
	i := &Identity{
		ratchets:      make(map[string][]byte),
		ratchetExpiry: make(map[string]int64),
		mutex:         &sync.RWMutex{},
	}

	// Generate X25519 key pair
	i.privateKey = make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, i.privateKey); err != nil {
		log.Printf("[DEBUG-1] Failed to generate X25519 private key: %v", err)
		return nil, err
	}

	var err error
	i.publicKey, err = curve25519.X25519(i.privateKey, curve25519.Basepoint)
	if err != nil {
		log.Printf("[DEBUG-1] Failed to generate X25519 public key: %v", err)
		return nil, err
	}

	// Generate Ed25519 signing keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("[DEBUG-1] Failed to generate Ed25519 keypair: %v", err)
		return nil, err
	}
	i.signingKey = privKey
	i.verificationKey = pubKey

	log.Printf("[DEBUG-7] Created new identity with hash: %x", i.Hash())
	return i, nil
}

func (i *Identity) GetPublicKey() []byte {
	combined := make([]byte, KEYSIZE/8)
	copy(combined[:KEYSIZE/16], i.publicKey)
	copy(combined[KEYSIZE/16:], i.verificationKey)
	return combined
}

func (i *Identity) GetPrivateKey() []byte {
	return append(i.privateKey, i.signingKey...)
}

func (i *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(i.signingKey, data)
}

func (i *Identity) Verify(data []byte, signature []byte) bool {
	return ed25519.Verify(i.verificationKey, data, signature)
}

func (i *Identity) Encrypt(plaintext []byte, ratchet []byte) ([]byte, error) {
	if i.publicKey == nil {
		log.Printf("[DEBUG-1] Encryption failed: identity has no public key")
		return nil, errors.New("encryption failed: identity does not hold a public key")
	}

	log.Printf("[DEBUG-7] Starting encryption for identity %s", i.GetHexHash())
	if ratchet != nil {
		log.Printf("[DEBUG-7] Using ratchet for encryption")
	}

	// Generate ephemeral keypair
	ephemeralPrivKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivKey); err != nil {
		return nil, err
	}

	ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Use ratchet key if provided, otherwise use identity public key
	targetKey := i.publicKey
	if ratchet != nil {
		targetKey = ratchet
	}

	// Generate shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivKey, targetKey)
	if err != nil {
		return nil, err
	}

	// Derive encryption key using HKDF
	kdf := hkdf.New(sha256.New, sharedSecret, i.GetSalt(), i.GetContext())
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}

	// Encrypt using AES-128-CBC with PKCS7 padding
	block, err := aes.NewCipher(key[:16]) // Use AES-128
	if err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := make([]byte, len(plaintext)+padding)
	copy(padtext, plaintext)
	for i := len(plaintext); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padtext))
	mode.CryptBlocks(ciphertext, padtext)

	// Calculate HMAC
	h := hmac.New(sha256.New, key)
	h.Write(append(ephemeralPubKey, append(iv, ciphertext...)...))
	mac := h.Sum(nil)

	// Combine all components into final token
	token := make([]byte, 0, len(ephemeralPubKey)+len(iv)+len(ciphertext)+len(mac))
	token = append(token, ephemeralPubKey...)
	token = append(token, iv...)
	token = append(token, ciphertext...)
	token = append(token, mac...)

	log.Printf("[DEBUG-7] Encryption completed successfully")
	return token, nil
}

func (i *Identity) Hash() []byte {
	h := sha256.New()
	h.Write(i.GetPublicKey())
	fullHash := h.Sum(nil)
	return fullHash[:TRUNCATED_HASHLENGTH/8]
}

func TruncatedHash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	fullHash := h.Sum(nil)
	return fullHash[:TRUNCATED_HASHLENGTH/8]
}

func GetRandomHash() []byte {
	randomData := make([]byte, TRUNCATED_HASHLENGTH/8)
	rand.Read(randomData)
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
	// TODO: Implement persistence
	// For now just create new identity
	return New()
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

	// Generate new ratchet key if none exists
	if len(i.ratchets) == 0 {
		key := make([]byte, RATCHETSIZE/8)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil
		}
		i.ratchets[string(key)] = key
		i.ratchetExpiry[string(key)] = time.Now().Unix() + RATCHET_EXPIRY
		return key
	}

	// Return most recent ratchet key
	var latestKey []byte
	var latestTime int64
	for key, expiry := range i.ratchetExpiry {
		if expiry > latestTime {
			latestTime = expiry
			latestKey = i.ratchets[key]
		}
	}
	return latestKey
}

func (i *Identity) Decrypt(ciphertextToken []byte, ratchets [][]byte, enforceRatchets bool, ratchetIDReceiver *common.RatchetIDReceiver) ([]byte, error) {
	if i.privateKey == nil {
		log.Printf("[DEBUG-1] Decryption failed: identity has no private key")
		return nil, errors.New("decryption failed because identity does not hold a private key")
	}

	log.Printf("[DEBUG-7] Starting decryption for identity %s", i.GetHexHash())
	if len(ratchets) > 0 {
		log.Printf("[DEBUG-7] Attempting decryption with %d ratchets", len(ratchets))
	}

	if len(ciphertextToken) <= KEYSIZE/8/2 {
		return nil, errors.New("decryption failed because the token size was invalid")
	}

	// Extract peer public key and ciphertext
	peerPubBytes := ciphertextToken[:KEYSIZE/8/2]
	ciphertext := ciphertextToken[KEYSIZE/8/2:]

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

	log.Printf("[DEBUG-7] Decryption completed successfully")
	return plaintext[:len(plaintext)-padding], nil
}

// Helper function to attempt decryption using a ratchet
func (i *Identity) tryRatchetDecryption(peerPubBytes, ciphertext, ratchet []byte) ([]byte, []byte, error) {
	// Convert ratchet to private key
	ratchetPriv := ratchet

	// Get ratchet ID
	ratchetPubBytes, err := curve25519.X25519(ratchetPriv, curve25519.Basepoint)
	if err != nil {
		log.Printf("[DEBUG-7] Failed to generate ratchet public key: %v", err)
		return nil, nil, err
	}
	ratchetID := i.GetRatchetID(ratchetPubBytes)

	log.Printf("[DEBUG-7] Decrypting with ratchet ID: %x", ratchetID)

	// Generate shared key
	sharedKey, err := curve25519.X25519(ratchetPriv, peerPubBytes)
	if err != nil {
		log.Printf("[DEBUG-7] Failed to generate shared key: %v", err)
		return nil, nil, err
	}

	// Derive key using HKDF
	hkdfReader := hkdf.New(sha256.New, sharedKey, i.GetSalt(), i.GetContext())
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		log.Printf("[DEBUG-7] Failed to derive key: %v", err)
		return nil, nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		log.Printf("[DEBUG-7] Failed to create cipher: %v", err)
		return nil, nil, err
	}

	// Extract IV and decrypt
	if len(ciphertext) < aes.BlockSize {
		log.Printf("[DEBUG-7] Ciphertext too short")
		return nil, nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	actualCiphertext := ciphertext[aes.BlockSize:]

	if len(actualCiphertext)%aes.BlockSize != 0 {
		log.Printf("[DEBUG-7] Ciphertext is not a multiple of block size")
		return nil, nil, errors.New("ciphertext is not a multiple of block size")
	}

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(actualCiphertext))
	mode.CryptBlocks(plaintext, actualCiphertext)

	// Remove padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		log.Printf("[DEBUG-7] Invalid padding")
		return nil, nil, errors.New("invalid padding")
	}

	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			log.Printf("[DEBUG-7] Invalid padding")
			return nil, nil, errors.New("invalid padding")
		}
	}

	log.Printf("[DEBUG-7] Decrypted successfully")
	return plaintext[:len(plaintext)-padding], ratchetID, nil
}

func (i *Identity) EncryptWithHMAC(plaintext []byte, key []byte) ([]byte, error) {
	// Encrypt with AES-CBC
	ciphertext, err := encryptAESCBC(key, plaintext)
	if err != nil {
		return nil, err
	}

	// Generate HMAC
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	// Combine ciphertext and HMAC
	return append(ciphertext, mac...), nil
}

func (i *Identity) DecryptWithHMAC(data []byte, key []byte) ([]byte, error) {
	if len(data) < sha256.Size {
		return nil, errors.New("data too short")
	}

	// Split HMAC and ciphertext
	macStart := len(data) - sha256.Size
	ciphertext := data[:macStart]
	messageMAC := data[macStart:]

	// Verify HMAC
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	expectedMAC := h.Sum(nil)
	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, errors.New("invalid HMAC")
	}

	// Decrypt
	return decryptAESCBC(key, ciphertext)
}

func (i *Identity) ToFile(path string) error {
	log.Printf("[DEBUG-7] Saving identity %s to file: %s", i.GetHexHash(), path)

	data := map[string]interface{}{
		"private_key":      i.privateKey,
		"public_key":       i.publicKey,
		"signing_key":      i.signingKey,
		"verification_key": i.verificationKey,
		"app_data":         i.appData,
	}

	file, err := os.Create(path)
	if err != nil {
		log.Printf("[DEBUG-1] Failed to create identity file: %v", err)
		return err
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(data); err != nil {
		log.Printf("[DEBUG-1] Failed to encode identity data: %v", err)
		return err
	}

	log.Printf("[DEBUG-7] Identity saved successfully")
	return nil
}

func RecallIdentity(path string) (*Identity, error) {
	log.Printf("[DEBUG-7] Attempting to recall identity from: %s", path)

	file, err := os.Open(path)
	if err != nil {
		log.Printf("[DEBUG-1] Failed to open identity file: %v", err)
		return nil, err
	}
	defer file.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		log.Printf("[DEBUG-1] Failed to decode identity data: %v", err)
		return nil, err
	}

	id := &Identity{
		privateKey:      data["private_key"].([]byte),
		publicKey:       data["public_key"].([]byte),
		signingKey:      data["signing_key"].(ed25519.PrivateKey),
		verificationKey: data["verification_key"].(ed25519.PublicKey),
		appData:         data["app_data"].([]byte),
		ratchets:        make(map[string][]byte),
		ratchetExpiry:   make(map[string]int64),
		mutex:           &sync.RWMutex{},
	}

	log.Printf("[DEBUG-7] Successfully recalled identity with hash: %s", id.GetHexHash())
	return id, nil
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
	hash := sha256.Sum256(ratchetPubBytes)
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
	// Generate Ed25519 signing keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %v", err)
	}

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
		signingKey:      privKey,
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

	log.Printf("[DEBUG-7] Rotating ratchet for identity %s", i.GetHexHash())

	// Generate new ratchet key
	newRatchet := make([]byte, RATCHETSIZE/8)
	if _, err := io.ReadFull(rand.Reader, newRatchet); err != nil {
		log.Printf("[DEBUG-1] Failed to generate new ratchet: %v", err)
		return nil, err
	}

	// Get public key for ratchet ID
	ratchetPub, err := curve25519.X25519(newRatchet, curve25519.Basepoint)
	if err != nil {
		log.Printf("[DEBUG-1] Failed to generate ratchet public key: %v", err)
		return nil, err
	}

	ratchetID := i.GetRatchetID(ratchetPub)
	expiry := time.Now().Unix() + RATCHET_EXPIRY

	// Store new ratchet
	i.ratchets[string(ratchetID)] = newRatchet
	i.ratchetExpiry[string(ratchetID)] = expiry

	log.Printf("[DEBUG-7] New ratchet generated with ID: %x, expiry: %d", ratchetID, expiry)

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
		log.Printf("[DEBUG-7] Cleaned up oldest ratchet with ID: %x", []byte(oldestID))
	}

	log.Printf("[DEBUG-7] Current number of active ratchets: %d", len(i.ratchets))
	return newRatchet, nil
}

func (i *Identity) GetRatchets() [][]byte {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	log.Printf("[DEBUG-7] Getting ratchets for identity %s", i.GetHexHash())

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

	log.Printf("[DEBUG-7] Retrieved %d active ratchets, cleaned up %d expired", len(ratchets), expired)
	return ratchets
}

func (i *Identity) CleanupExpiredRatchets() {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	log.Printf("[DEBUG-7] Starting ratchet cleanup for identity %s", i.GetHexHash())

	now := time.Now().Unix()
	cleaned := 0
	for id, expiry := range i.ratchetExpiry {
		if expiry <= now {
			delete(i.ratchets, id)
			delete(i.ratchetExpiry, id)
			cleaned++
		}
	}

	log.Printf("[DEBUG-7] Cleaned up %d expired ratchets, %d remaining", cleaned, len(i.ratchets))
}

// ValidateAnnounce validates an announce packet's signature
func (i *Identity) ValidateAnnounce(data []byte, destHash []byte, appData []byte) bool {
	if i == nil || len(data) < ed25519.SignatureSize {
		return false
	}

	signatureStart := len(data) - ed25519.SignatureSize
	signature := data[signatureStart:]
	signedData := append(destHash, appData...)

	return ed25519.Verify(i.verificationKey, signedData, signature)
}
