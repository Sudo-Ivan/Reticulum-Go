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
	}

	// Generate X25519 key pair
	i.privateKey = make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, i.privateKey); err != nil {
		return nil, err
	}

	var err error
	i.publicKey, err = curve25519.X25519(i.privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Generate Ed25519 signing keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	i.signingKey = privKey
	i.verificationKey = pubKey

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
		return nil, errors.New("encryption failed: identity does not hold a public key")
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

	if len(destHash) > TRUNCATED_HASHLENGTH/8 {
		destHash = destHash[:TRUNCATED_HASHLENGTH/8]
	}

	announced := &Identity{}
	announced.publicKey = publicKey[:KEYSIZE/16]
	announced.verificationKey = publicKey[KEYSIZE/16:]

	signedData := append(destHash, publicKey...)
	signedData = append(signedData, appData...)

	if !announced.Verify(signedData, signature) {
		return false
	}

	Remember(packet, destHash, publicKey, appData)
	return true
}

func FromPublicKey(publicKey []byte) *Identity {
	if len(publicKey) != KEYSIZE/8 {
		return nil
	}

	i := &Identity{
		publicKey:       publicKey[:KEYSIZE/16],
		verificationKey: publicKey[KEYSIZE/16:],
		ratchets:        make(map[string][]byte),
		ratchetExpiry:   make(map[string]int64),
	}

	return i
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
		return nil, errors.New("decryption failed because identity does not hold a private key")
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

	return plaintext[:len(plaintext)-padding], nil
}

// Helper function to attempt decryption using a ratchet
func (i *Identity) tryRatchetDecryption(peerPubBytes, ciphertext, ratchet []byte) ([]byte, []byte, error) {
	// Convert ratchet to private key
	ratchetPriv := ratchet

	// Get ratchet ID
	ratchetPubBytes, err := curve25519.X25519(ratchetPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	ratchetID := i.GetRatchetID(ratchetPubBytes)

	// Generate shared key
	sharedKey, err := curve25519.X25519(ratchetPriv, peerPubBytes)
	if err != nil {
		return nil, nil, err
	}

	// Derive key using HKDF
	hkdfReader := hkdf.New(sha256.New, sharedKey, i.GetSalt(), i.GetContext())
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, err
	}

	// Extract IV and decrypt
	if len(ciphertext) < aes.BlockSize {
		return nil, nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	actualCiphertext := ciphertext[aes.BlockSize:]

	if len(actualCiphertext)%aes.BlockSize != 0 {
		return nil, nil, errors.New("ciphertext is not a multiple of block size")
	}

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(actualCiphertext))
	mode.CryptBlocks(plaintext, actualCiphertext)

	// Remove padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, nil, errors.New("invalid padding")
	}

	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, nil, errors.New("invalid padding")
		}
	}

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
	data := map[string]interface{}{
		"private_key":      i.privateKey,
		"public_key":       i.publicKey,
		"signing_key":      i.signingKey,
		"verification_key": i.verificationKey,
		"app_data":         i.appData,
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(data)
}

func RecallIdentity(path string) (*Identity, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return nil, err
	}

	// Reconstruct identity from saved data
	id := &Identity{
		privateKey:      data["private_key"].([]byte),
		publicKey:       data["public_key"].([]byte),
		signingKey:      data["signing_key"].(ed25519.PrivateKey),
		verificationKey: data["verification_key"].(ed25519.PublicKey),
		appData:         data["app_data"].([]byte),
		ratchets:        make(map[string][]byte),
		ratchetExpiry:   make(map[string]int64),
	}

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
