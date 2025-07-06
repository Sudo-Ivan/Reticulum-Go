package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestGenerateAESKeys(t *testing.T) {
	t.Run("GenerateAES256Key", func(t *testing.T) {
		key, err := GenerateAES256Key()
		if err != nil {
			t.Fatalf("GenerateAES256Key failed: %v", err)
		}
		if len(key) != AES256KeySize {
			t.Errorf("Expected key size %d, got %d", AES256KeySize, len(key))
		}
	})

	t.Run("GenerateAESKey_AllSizes", func(t *testing.T) {
		sizes := []int{AES128KeySize, AES192KeySize, AES256KeySize}
		for _, size := range sizes {
			key, err := GenerateAESKey(size)
			if err != nil {
				t.Fatalf("GenerateAESKey(%d) failed: %v", size, err)
			}
			if len(key) != size {
				t.Errorf("Expected key size %d, got %d", size, len(key))
			}
		}
	})

	t.Run("GenerateAESKey_InvalidSize", func(t *testing.T) {
		invalidSizes := []int{8, 15, 17, 23, 25, 31, 33, 64}
		for _, size := range invalidSizes {
			_, err := GenerateAESKey(size)
			if err == nil {
				t.Errorf("GenerateAESKey(%d) should have failed but didn't", size)
			}
		}
	})
}

func TestAES256CBCEncryptionDecryption(t *testing.T) {
	key, err := GenerateAES256Key()
	if err != nil {
		t.Fatalf("Failed to generate AES-256 key: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"ShortMessage", []byte("Hello")},
		{"BlockSizeMessage", []byte("This is 16 bytes")},
		{"LongMessage", []byte("This is a longer message that spans multiple AES blocks and tests the padding.")},
		{"EmptyMessage", []byte("")},
		{"SingleByte", []byte("A")},
		{"ExactlyTwoBlocks", []byte("This is exactly 32 bytes long!!!")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := EncryptAES256CBC(key, tc.plaintext)
			if err != nil {
				t.Fatalf("EncryptAES256CBC failed: %v", err)
			}

			decrypted, err := DecryptAES256CBC(key, ciphertext)
			if err != nil {
				t.Fatalf("DecryptAES256CBC failed: %v", err)
			}

			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("Decrypted text does not match original plaintext.\nGot:  %q (%x)\nWant: %q (%x)",
					decrypted, decrypted, tc.plaintext, tc.plaintext)
			}
		})
	}
}

func TestAES256CBC_InvalidKeySize(t *testing.T) {
	plaintext := []byte("test message")

	invalidKeys := [][]byte{
		make([]byte, 16), // AES-128
		make([]byte, 24), // AES-192
		make([]byte, 15), // Too short
		make([]byte, 33), // Too long
		nil,              // Nil key
	}

	for i, key := range invalidKeys {
		t.Run(fmt.Sprintf("InvalidKey_%d", i), func(t *testing.T) {
			_, err := EncryptAES256CBC(key, plaintext)
			if err == nil {
				t.Error("EncryptAES256CBC should have failed with invalid key size")
			}

			// Test with some dummy ciphertext
			dummyCiphertext := make([]byte, 32) // Just enough for IV + one block
			rand.Read(dummyCiphertext)
			_, err = DecryptAES256CBC(key, dummyCiphertext)
			if err == nil {
				t.Error("DecryptAES256CBC should have failed with invalid key size")
			}
		})
	}
}

func TestAESCBCEncryptionDecryption(t *testing.T) {
	keySizes := []int{AES128KeySize, AES192KeySize, AES256KeySize}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("AES_%d", keySize*8), func(t *testing.T) {
			key, err := GenerateAESKey(keySize)
			if err != nil {
				t.Fatalf("Failed to generate AES-%d key: %v", keySize*8, err)
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
		})
	}
}

func TestDecryptAESCBCErrorCases(t *testing.T) {
	key, err := GenerateAES256Key()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("CiphertextTooShort", func(t *testing.T) {
		shortCiphertext := []byte{0x01, 0x02, 0x03} // Less than AES block size
		_, err := DecryptAESCBC(key, shortCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for ciphertext shorter than block size")
		}
	})

	t.Run("InvalidKeySize", func(t *testing.T) {
		invalidKey := make([]byte, 17)      // Invalid key size
		validCiphertext := make([]byte, 32) // IV + one block
		rand.Read(validCiphertext)

		_, err := DecryptAESCBC(invalidKey, validCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for invalid key size")
		}
	})

	t.Run("CiphertextNotMultipleOfBlockSize", func(t *testing.T) {
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		invalidCiphertext := append(iv, []byte{0x01, 0x02, 0x03}...) // IV + data not multiple of block size
		_, err := DecryptAESCBC(key, invalidCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for ciphertext not multiple of block size")
		}
	})

	t.Run("InvalidPadding", func(t *testing.T) {
		// Create a valid ciphertext first
		plaintext := []byte("valid data")
		ciphertext, err := EncryptAESCBC(key, plaintext)
		if err != nil {
			t.Fatalf("Failed to create test ciphertext: %v", err)
		}

		// Corrupt the last byte (which affects padding)
		corruptedCiphertext := make([]byte, len(ciphertext))
		copy(corruptedCiphertext, ciphertext)
		corruptedCiphertext[len(corruptedCiphertext)-1] ^= 0xFF

		_, err = DecryptAESCBC(key, corruptedCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for corrupted padding")
		}
	})

	t.Run("EmptyPlaintext", func(t *testing.T) {
		// Create a ciphertext that would result in empty plaintext
		invalidCiphertext := make([]byte, aes.BlockSize) // Only IV, no data
		_, err := DecryptAESCBC(key, invalidCiphertext)
		if err == nil {
			t.Error("DecryptAESCBC should have failed for empty ciphertext data")
		}
	})
}

func TestConstants(t *testing.T) {
	if AES128KeySize != 16 {
		t.Errorf("AES128KeySize should be 16, got %d", AES128KeySize)
	}
	if AES192KeySize != 24 {
		t.Errorf("AES192KeySize should be 24, got %d", AES192KeySize)
	}
	if AES256KeySize != 32 {
		t.Errorf("AES256KeySize should be 32, got %d", AES256KeySize)
	}
	if DefaultKeySize != AES256KeySize {
		t.Errorf("DefaultKeySize should be AES256KeySize (%d), got %d", AES256KeySize, DefaultKeySize)
	}
}

func BenchmarkAES256CBC(b *testing.B) {
	key, err := GenerateAES256Key()
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	data := make([]byte, 1024) // 1KB of data
	rand.Read(data)

	b.Run("Encrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := EncryptAES256CBC(key, data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	ciphertext, _ := EncryptAES256CBC(key, data)
	b.Run("Decrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := DecryptAES256CBC(key, ciphertext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
