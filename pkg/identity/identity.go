package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

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
	return h.Sum(nil)
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
