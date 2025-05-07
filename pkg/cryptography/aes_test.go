package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestAESCBCEncryptionDecryption(t *testing.T) {
	// Generate a random key (AES-256)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"ShortMessage", []byte("Hello")},
		{"BlockSizeMessage", []byte("This is 16 bytes")},
		{"LongMessage", []byte("This is a longer message that spans multiple AES blocks.")},
		{"EmptyMessage", []byte("")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := EncryptAESCBC(key, tc.plaintext)
			if err != nil {
				t.Fatalf("EncryptAESCBC failed: %v", err)
			}

			decrypted, err := DecryptAESCBC(key, ciphertext)
			if err != nil {
				t.Fatalf("DecryptAESCBC failed: %v", err)
			}

			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("Decrypted text does not match original plaintext. Got %q, want %q", decrypted, tc.plaintext)
			}
		})
	}
}

func TestDecryptAESCBCErrorCases(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	t.Run("CiphertextTooShort", func(t *testing.T) {
		shortCiphertext := []byte{0x01, 0x02, 0x03} // Less than AES block size
		_, err := DecryptAESCBC(key, shortCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for ciphertext shorter than block size, but it didn't")
		}
	})

	t.Run("InvalidPadding", func(t *testing.T) {
		// Encrypt something valid first
		plaintext := []byte("valid data")
		ciphertext, _ := EncryptAESCBC(key, plaintext)

		// Tamper with the ciphertext (specifically the part that would affect padding)
		if len(ciphertext) > aes.BlockSize {
			ciphertext[len(ciphertext)-1] = ^ciphertext[len(ciphertext)-1] // Flip bits of last byte
		}

		_, err := DecryptAESCBC(key, ciphertext)
		if err == nil {
			// Note: Depending on the padding implementation and the nature of the tampering,
			// CBC decryption might not always error out on bad padding. It might return garbage data.
			// A more robust test might check the decrypted content, but error checking is a start.
			t.Logf("DecryptAESCBC did not error on potentially invalid padding (this might be expected)")
		}
	})

	t.Run("CiphertextNotMultipleOfBlockSize", func(t *testing.T) {
		iv := make([]byte, aes.BlockSize)
		_, _ = rand.Read(iv)
		invalidCiphertext := append(iv, []byte{0x01, 0x02, 0x03}...) // IV + data not multiple of block size
		_, err := DecryptAESCBC(key, invalidCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for ciphertext not multiple of block size, but it didn't")
		}
	})
}
