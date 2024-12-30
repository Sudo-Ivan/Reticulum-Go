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

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize          = 512 // Combined size of encryption and signing keys
	RatchetSize      = 256
	RatchetExpiry    = 2592000 // 30 days in seconds
	TruncatedHashLen = 128     // bits
	NameHashLength   = 80      // bits
	TokenOverhead    = 16      // bytes
	AESBlockSize     = 16      // bytes
	HashLength       = 256     // bits
	SigLength        = KeySize // bits
	HMACKeySize      = 32      // bytes
)

type Identity struct {
	privateKey      []byte
	publicKey       []byte
	signingKey      ed25519.PrivateKey
	verificationKey ed25519.PublicKey
	ratchets        map[string][]byte
	ratchetExpiry   map[string]int64
	mutex           sync.RWMutex
	appData         []byte
}

var (
	knownDestinations  = make(map[string][]interface{})
	knownRatchets      = make(map[string][]byte)
	ratchetPersistLock sync.Mutex
)

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

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
	combined := make([]byte, KeySize/8)
	copy(combined[:KeySize/16], i.publicKey)
	copy(combined[KeySize/16:], i.verificationKey)
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
	// Generate ephemeral key pair
	ephemeralPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivate); err != nil {
		return nil, err
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var targetKey []byte
	if ratchet != nil {
		targetKey = ratchet
	} else {
		targetKey = i.publicKey
	}

	sharedSecret, err := curve25519.X25519(ephemeralPrivate, targetKey)
	if err != nil {
		return nil, err
	}

	// Generate encryption key using HKDF
	hkdf := hkdf.New(sha256.New, sharedSecret, i.Hash(), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	// Encrypt using AES-GCM
	ciphertext, err := encryptAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	return append(ephemeralPublic, ciphertext...), nil
}

func (i *Identity) Hash() []byte {
	h := sha256.New()
	h.Write(i.GetPublicKey())
	fullHash := h.Sum(nil)
	return fullHash[:TruncatedHashLen/8]
}

func TruncatedHash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	fullHash := h.Sum(nil)
	return fullHash[:TruncatedHashLen/8]
}

func GetRandomHash() []byte {
	randomData := make([]byte, TruncatedHashLen/8)
	rand.Read(randomData)
	return TruncatedHash(randomData)
}

func Remember(packetHash, destHash []byte, publicKey []byte, appData []byte) {
	if len(destHash) > TruncatedHashLen/8 {
		destHash = destHash[:TruncatedHashLen/8]
	}

	knownDestinations[string(destHash)] = []interface{}{
		time.Now().Unix(),
		packetHash,
		publicKey,
		appData,
	}
}

func ValidateAnnounce(packet []byte, destHash []byte, publicKey []byte, signature []byte, appData []byte) bool {
	if len(publicKey) != KeySize/8 {
		return false
	}

	if len(destHash) > TruncatedHashLen/8 {
		destHash = destHash[:TruncatedHashLen/8]
	}

	announced := &Identity{}
	announced.publicKey = publicKey[:KeySize/16]
	announced.verificationKey = publicKey[KeySize/16:]

	signedData := append(destHash, publicKey...)
	signedData = append(signedData, appData...)

	if !announced.Verify(signedData, signature) {
		return false
	}

	Remember(packet, destHash, publicKey, appData)
	return true
}

func FromPublicKey(publicKey []byte) *Identity {
	if len(publicKey) != KeySize/8 {
		return nil
	}

	i := &Identity{
		publicKey:       publicKey[:KeySize/16],
		verificationKey: publicKey[KeySize/16:],
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
	hmacKey := make([]byte, HMACKeySize)
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
		key := make([]byte, RatchetSize/8)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil
		}
		i.ratchets[string(key)] = key
		i.ratchetExpiry[string(key)] = time.Now().Unix() + RatchetExpiry
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

func (i *Identity) EncryptSymmetric(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}
	return encryptAESGCM(key, plaintext)
}

func (i *Identity) DecryptSymmetric(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}
	return decryptAESGCM(key, ciphertext)
}

func (i *Identity) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < curve25519.PointSize {
		return nil, errors.New("ciphertext too short")
	}

	ephemeralPublic := ciphertext[:curve25519.PointSize]
	encryptedData := ciphertext[curve25519.PointSize:]

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(i.privateKey, ephemeralPublic)
	if err != nil {
		return nil, err
	}

	// Derive key using HKDF
	hkdf := hkdf.New(sha256.New, sharedSecret, i.Hash(), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	// Decrypt data
	return decryptAESGCM(key, encryptedData)
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
