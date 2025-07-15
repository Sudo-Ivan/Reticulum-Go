package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// AES256KeySize is the size of an AES-256 key in bytes.
	AES256KeySize = 32 // 256 bits
)

// GenerateAES256Key generates a random AES-256 key.
func GenerateAES256Key() ([]byte, error) {
	key := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAES256CBC encrypts data using AES-256 in CBC mode.
// The IV is prepended to the ciphertext.
func EncryptAES256CBC(key, plaintext []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, errors.New("invalid key size: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random IV.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Add PKCS7 padding.
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := make([]byte, len(plaintext)+padding)
	copy(padtext, plaintext)
	for i := len(plaintext); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// Encrypt the data.
	mode := cipher.NewCBCEncrypter(block, iv) // #nosec G407
	ciphertext := make([]byte, len(padtext))
	mode.CryptBlocks(ciphertext, padtext)

	// Prepend the IV to the ciphertext.
	return append(iv, ciphertext...), nil
}

// DecryptAES256CBC decrypts data using AES-256 in CBC mode.
// It assumes the IV is prepended to the ciphertext.
func DecryptAES256CBC(key, ciphertext []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, errors.New("invalid key size: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext is too short")
	}

	// Extract the IV from the beginning of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	// Decrypt the data.
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding.
	if len(plaintext) == 0 {
		return nil, errors.New("invalid padding: plaintext is empty")
	}

	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, errors.New("invalid padding size")
	}
	if len(plaintext) < padding {
		return nil, errors.New("invalid padding: padding size is larger than plaintext")
	}

	// Verify the padding bytes.
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, errors.New("invalid padding bytes")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}
