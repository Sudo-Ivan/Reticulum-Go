package cryptography

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, err
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func DeriveSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, peerPublicKey)
}
