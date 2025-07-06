package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// AES key sizes in bytes
	AES128KeySize = 16 // 128 bits
	AES192KeySize = 24 // 192 bits
	AES256KeySize = 32 // 256 bits

	// Default to AES-256
	DefaultKeySize = AES256KeySize
)

// GenerateAESKey generates a random AES key of the specified size
func GenerateAESKey(keySize int) ([]byte, error) {
	if keySize != AES128KeySize && keySize != AES192KeySize && keySize != AES256KeySize {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateAES256Key generates a random AES-256 key (default)
func GenerateAES256Key() ([]byte, error) {
	return GenerateAESKey(AES256KeySize)
}

// EncryptAES256CBC encrypts data using AES-256 in CBC mode
func EncryptAES256CBC(key, plaintext []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	return EncryptAESCBC(key, plaintext)
}

// DecryptAES256CBC decrypts data using AES-256 in CBC mode
func DecryptAES256CBC(key, ciphertext []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}
	return DecryptAESCBC(key, ciphertext)
}

// EncryptAESCBC encrypts data using AES in CBC mode (accepts any valid AES key size)
func EncryptAESCBC(key, plaintext []byte) ([]byte, error) {
	// Validate key size
	if len(key) != AES128KeySize && len(key) != AES192KeySize && len(key) != AES256KeySize {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

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

	return append(iv, ciphertext...), nil
}

// DecryptAESCBC decrypts data using AES in CBC mode (accepts any valid AES key size)
func DecryptAESCBC(key, ciphertext []byte) ([]byte, error) {
	// Validate key size
	if len(key) != AES128KeySize && len(key) != AES192KeySize && len(key) != AES256KeySize {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

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
	if len(plaintext) == 0 {
		return nil, errors.New("invalid padding: empty plaintext")
	}

	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plaintext) {
		return nil, errors.New("invalid PKCS7 padding")
	}

	// Verify all padding bytes are correct
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}
