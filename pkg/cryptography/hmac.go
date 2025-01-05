package cryptography

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

func GenerateHMACKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func ComputeHMAC(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

func ValidateHMAC(key, message, messageHMAC []byte) bool {
	expectedHMAC := ComputeHMAC(key, message)
	return hmac.Equal(messageHMAC, expectedHMAC)
}
