package cryptography

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	secret := []byte("test-secret")
	salt := []byte("test-salt")
	info := []byte("test-info")
	length := 32 // Desired key length

	key1, err := DeriveKey(secret, salt, info, length)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != length {
		t.Errorf("DeriveKey returned key of length %d; want %d", len(key1), length)
	}

	// Derive another key with the same parameters, should be identical
	key2, err := DeriveKey(secret, salt, info, length)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Errorf("DeriveKey is not deterministic. Got %x and %x for the same inputs", key1, key2)
	}

	// Derive a key with different info, should be different
	differentInfo := []byte("different-info")
	key3, err := DeriveKey(secret, salt, differentInfo, length)
	if err != nil {
		t.Fatalf("DeriveKey with different info failed: %v", err)
	}
	if bytes.Equal(key1, key3) {
		t.Errorf("DeriveKey produced the same key for different info strings")
	}

	// Derive a key with different salt, should be different
	differentSalt := []byte("different-salt")
	key4, err := DeriveKey(secret, differentSalt, info, length)
	if err != nil {
		t.Fatalf("DeriveKey with different salt failed: %v", err)
	}
	if bytes.Equal(key1, key4) {
		t.Errorf("DeriveKey produced the same key for different salts")
	}

	// Derive a key with different secret, should be different
	differentSecret := []byte("different-secret")
	key5, err := DeriveKey(differentSecret, salt, info, length)
	if err != nil {
		t.Fatalf("DeriveKey with different secret failed: %v", err)
	}
	if bytes.Equal(key1, key5) {
		t.Errorf("DeriveKey produced the same key for different secrets")
	}

	// Derive a key with different length
	differentLength := 64
	key6, err := DeriveKey(secret, salt, info, differentLength)
	if err != nil {
		t.Fatalf("DeriveKey with different length failed: %v", err)
	}
	if len(key6) != differentLength {
		t.Errorf("DeriveKey returned key of length %d; want %d", len(key6), differentLength)
	}
}

func TestDeriveKeyEdgeCases(t *testing.T) {
	secret := []byte("test-secret")
	salt := []byte("test-salt")
	info := []byte("test-info")

	t.Run("EmptySecret", func(t *testing.T) {
		_, err := DeriveKey([]byte{}, salt, info, 32)
		if err != nil {
			t.Errorf("DeriveKey failed with empty secret: %v", err)
		}
	})

	t.Run("EmptySalt", func(t *testing.T) {
		_, err := DeriveKey(secret, []byte{}, info, 32)
		if err != nil {
			t.Errorf("DeriveKey failed with empty salt: %v", err)
		}
	})

	t.Run("EmptyInfo", func(t *testing.T) {
		_, err := DeriveKey(secret, salt, []byte{}, 32)
		if err != nil {
			t.Errorf("DeriveKey failed with empty info: %v", err)
		}
	})

	t.Run("ZeroLength", func(t *testing.T) {
		key, err := DeriveKey(secret, salt, info, 0)
		if err != nil {
			t.Errorf("DeriveKey failed with zero length: %v", err)
		}
		if len(key) != 0 {
			t.Errorf("DeriveKey with zero length returned non-empty key: %x", key)
		}
	})
}
