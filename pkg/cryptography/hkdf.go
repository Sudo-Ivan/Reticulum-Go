package cryptography

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}
