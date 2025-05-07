package cryptography

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeyPair(t *testing.T) {
	priv1, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if len(priv1) != curve25519.ScalarSize {
		t.Errorf("Private key length is %d, want %d", len(priv1), curve25519.ScalarSize)
	}
	if len(pub1) != curve25519.PointSize {
		t.Errorf("Public key length is %d, want %d", len(pub1), curve25519.PointSize)
	}

	// Generate another pair, should be different
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Second GenerateKeyPair failed: %v", err)
	}
	if bytes.Equal(priv1, priv2) {
		t.Error("Generated private keys are identical")
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("Generated public keys are identical")
	}
}

func TestDeriveSharedSecret(t *testing.T) {
	privA, pubA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A failed: %v", err)
	}
	privB, pubB, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B failed: %v", err)
	}

	secretA, err := DeriveSharedSecret(privA, pubB)
	if err != nil {
		t.Fatalf("DeriveSharedSecret (A perspective) failed: %v", err)
	}

	secretB, err := DeriveSharedSecret(privB, pubA)
	if err != nil {
		t.Fatalf("DeriveSharedSecret (B perspective) failed: %v", err)
	}

	if !bytes.Equal(secretA, secretB) {
		t.Errorf("Derived shared secrets do not match:\nSecret A: %x\nSecret B: %x", secretA, secretB)
	}

	if len(secretA) != curve25519.PointSize { // Shared secret length
		t.Errorf("Shared secret length is %d, want %d", len(secretA), curve25519.PointSize)
	}
}
