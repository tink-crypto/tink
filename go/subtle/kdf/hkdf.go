package kdf

//Package kdf is just a wrapper arround the golang kdf method

import (
	"hash"

	"github.com/google/tink/go/subtle"
	"golang.org/x/crypto/hkdf"
)

//HKDF is shallow wrapper around x/crypto/HKDF
type HKDF struct {
}

// GenerateKeyWithHash is just a shallow wrapper around x/crypto/hkdf, takes an actual hash function
func (h *HKDF) GenerateKeyWithHash(hash func() hash.Hash, secret, salt, info []byte, keySize int) ([]byte, error) {
	keyReader := hkdf.New(hash, secret, salt, info)
	return generateIV(keySize, keyReader)
}

// GenerateKey is just a shallow wrapper around x/crypto/hkdf, takes the name of a hash function
func (h *HKDF) GenerateKey(hashName string, secret, salt, info []byte, keySize int) ([]byte, error) {
	hash := subtle.GetHashFunc(hashName)
	return h.GenerateKeyWithHash(hash, secret, salt, info, keySize)
}
