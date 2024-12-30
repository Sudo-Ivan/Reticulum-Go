package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"time"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"bytes"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"github.com/Sudo-Ivan/reticulum-go/pkg/common"
)

const (
	KeySize          = 512 // Combined size of encryption and signing keys
	RatchetSize      = 256
	RatchetExpiry    = 2592000 // 30 days in seconds
	TruncatedHashLen = 128     // bits
)

type Identity struct {
	privateKey       []byte
	publicKey        []byte
	signingKey       ed25519.PrivateKey
	verificationKey  ed25519.PublicKey
	ratchets        map[string][]byte
	ratchetExpiry   map[string]int64
	mutex           sync.RWMutex
}

func New() (*Identity, error) {
	i := &Identity{
		ratchets:      make(map[string][]byte),
		ratchetExpiry: make(map[string]int64),
	}

	// Generate X25519 key pair
	var err error
	i.privateKey = make([]byte, curve25519.ScalarSize)
	if _, err = io.ReadFull(rand.Reader, i.privateKey); err != nil {
		return nil, err
	}

	// Generate public key
	i.publicKey, err = curve25519.X25519(i.privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Generate Ed25519 signing keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	i.signingKey = privateKey
	i.verificationKey = publicKey

	return i, nil
}

func FromBytes(data []byte) (*Identity, error) {
	if len(data) != KeySize/8 {
		return nil, errors.New("invalid key size")
	}

	i := &Identity{
		ratchets:      make(map[string][]byte),
		ratchetExpiry: make(map[string]int64),
	}

	// First 32 bytes are X25519 private key
	i.privateKey = data[:32]
	
	var err error
	i.publicKey, err = curve25519.X25519(i.privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Next 32 bytes are Ed25519 private key
	i.signingKey = ed25519.PrivateKey(data[32:])
	i.verificationKey = i.signingKey.Public().(ed25519.PublicKey)

	return i, nil
}

func (i *Identity) ToBytes() []byte {
	data := make([]byte, KeySize/8)
	copy(data[:32], i.privateKey)
	copy(data[32:], i.signingKey)
	return data
}

func (i *Identity) SaveToFile(path string) error {
	return os.WriteFile(path, i.ToBytes(), 0600)
}

func LoadFromFile(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromBytes(data)
}

func (i *Identity) Encrypt(plaintext []byte, ratchets []byte) ([]byte, error) {
	// Generate ephemeral key pair
	ephemeralPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivate); err != nil {
		return nil, err
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Perform key exchange
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, i.publicKey)
	if err != nil {
		return nil, err
	}

	// Generate AES key from shared secret using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret, nil, nil)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, aesKey); err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine ephemeral public key, nonce and ciphertext
	result := make([]byte, len(ephemeralPublic)+len(nonce)+len(ciphertext))
	copy(result, ephemeralPublic)
	copy(result[len(ephemeralPublic):], nonce)
	copy(result[len(ephemeralPublic)+len(nonce):], ciphertext)

	return result, nil
}

func (i *Identity) Decrypt(ciphertext []byte, ratchets []byte) ([]byte, error) {
	if len(ciphertext) <= curve25519.ScalarSize {
		return nil, errors.New("invalid ciphertext")
	}

	// Extract ephemeral public key
	ephemeralPublic := ciphertext[:curve25519.ScalarSize]

	// Perform key exchange
	sharedSecret, err := curve25519.X25519(i.privateKey, ephemeralPublic)
	if err != nil {
		return nil, err
	}

	// Generate AES key from shared secret using HKDF
	hash := sha256.New
	hkdf := hkdf.New(hash, sharedSecret, nil, nil)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, aesKey); err != nil {
		return nil, err
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce and encrypted data
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < curve25519.ScalarSize+nonceSize {
		return nil, errors.New("invalid ciphertext")
	}

	nonce := ciphertext[curve25519.ScalarSize : curve25519.ScalarSize+nonceSize]
	encryptedData := ciphertext[curve25519.ScalarSize+nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (i *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(i.signingKey, message)
}

func (i *Identity) Verify(message, signature []byte) bool {
	return ed25519.Verify(i.verificationKey, message, signature)
}

func (i *Identity) GetPublicKey() []byte {
	return append([]byte{}, i.publicKey...)
}

func (i *Identity) AddRatchet(ratchetID string, ratchetKey []byte) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	
	i.ratchets[ratchetID] = ratchetKey
	i.ratchetExpiry[ratchetID] = time.Now().Unix() + RatchetExpiry
}

func (i *Identity) GetRatchet(ratchetID string) []byte {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	if expiry, ok := i.ratchetExpiry[ratchetID]; ok {
		if time.Now().Unix() < expiry {
			return i.ratchets[ratchetID]
		}
		// Cleanup expired ratchet
		delete(i.ratchets, ratchetID)
		delete(i.ratchetExpiry, ratchetID)
	}
	return nil
}

// Helper functions
func TruncatedHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:TruncatedHashLen/8]
}

func FullHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func HashFromHex(hexHash string) ([]byte, error) {
	if len(hexHash) != TruncatedHashLen/4 { // hex string is twice the length of bytes
		return nil, errors.New("invalid hash length")
	}
	
	hash := make([]byte, TruncatedHashLen/8)
	_, err := hex.Decode(hash, []byte(hexHash))
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func Recall(hash []byte) (*Identity, error) {
	// Get config path from environment or default location
	configDir := os.Getenv("RETICULUM_CONFIG_DIR")
	if configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(homeDir, ".reticulum")
	}

	// Create identities directory if it doesn't exist
	identitiesPath := filepath.Join(configDir, "identities")
	if err := os.MkdirAll(identitiesPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create identities directory: %w", err)
	}

	// Convert hash to hex for filename
	hashHex := hex.EncodeToString(hash)
	identityPath := filepath.Join(identitiesPath, hashHex)

	// Check if identity file exists
	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		return nil, errors.New("identity not found")
	}

	// Load identity from file
	identity, err := LoadFromFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity: %w", err)
	}

	// Verify the loaded identity matches the requested hash
	if !bytes.Equal(TruncatedHash(identity.GetPublicKey()), hash) {
		return nil, errors.New("identity hash mismatch")
	}

	return identity, nil
}

func LoadIdentity(cfg *common.ReticulumConfig) (*Identity, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	// Try to load existing identity
	identityPath := filepath.Join(filepath.Dir(cfg.ConfigPath), "identity")
	if _, err := os.Stat(identityPath); err == nil {
		// Identity exists, load it
		return LoadFromFile(identityPath)
	}

	// Create new identity
	identity, err := New()
	if err != nil {
		return nil, fmt.Errorf("failed to create new identity: %w", err)
	}

	// Save the new identity
	if err := identity.SaveToFile(identityPath); err != nil {
		return nil, fmt.Errorf("failed to save new identity: %w", err)
	}

	return identity, nil
}

func (i *Identity) GetCurrentRatchetKey() []byte {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	
	// Generate new ratchet key if none exists
	if len(i.ratchets) == 0 {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil
		}
		ratchetID := fmt.Sprintf("%d", time.Now().Unix())
		i.AddRatchet(ratchetID, key)
		return key
	}
	
	// Return most recent ratchet key
	var latestTime int64
	var latestKey []byte
	
	for id, key := range i.ratchets {
		if expiry, ok := i.ratchetExpiry[id]; ok {
			if expiry > latestTime {
				latestTime = expiry
				latestKey = key
			}
		}
	}
	
	return latestKey
}

func (i *Identity) EncryptSymmetric(plaintext []byte) ([]byte, error) {
	key := i.GetCurrentRatchetKey()
	if key == nil {
		return nil, errors.New("no ratchet key available")
	}
	
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
	
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (i *Identity) DecryptSymmetric(ciphertext []byte) ([]byte, error) {
	key := i.GetCurrentRatchetKey()
	if key == nil {
		return nil, errors.New("no ratchet key available")
	}
	
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
		return nil, errors.New("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return plaintext, nil
}

func (i *Identity) Hash() []byte {
	return TruncatedHash(i.publicKey)
}

func (i *Identity) Hex() string {
	return hex.EncodeToString(i.Hash())
} 