package cryptography

import (
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

const (
	SHA256Size = 32
)

// GetBasepoint returns the standard Curve25519 basepoint
func GetBasepoint() []byte {
	return curve25519.Basepoint
}

func Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
