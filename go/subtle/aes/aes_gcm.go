// Copyright 2017 Google Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink/primitives"
)

const (
	// All instances of this class use a 12 byte IV and 16 byte tag
	AES_GCM_IV_SIZE  = 12
	AES_GCM_TAG_SIZE = 16
)

// AesGcm is an implementation of Aead interface.
type AesGcm struct {
	Key []byte
}

// Assert that AesGcm implements the Aead interface.
var _ tink.Aead = (*AesGcm)(nil)

// NewAesGcm returns an AesGcm instance.
// The key argument should be the AES key, either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func NewAesGcm(key []byte) (*AesGcm, error) {
	keySize := uint32(len(key))
	if err := ValidateAesKeySize(keySize); err != nil {
		return nil, fmt.Errorf("aes_gcm: %s", err)
	}
	return &AesGcm{Key: key}, nil
}

// ValidateAesKeySize checks if the given key size is a valid AES key size.
func ValidateAesKeySize(sizeInBytes uint32) error {
	switch sizeInBytes {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("invalid AES key size %d", sizeInBytes)
	}
}

// Encrypt encrypts {@code pt} with {@code aad} as additional
// authenticated data. The resulting ciphertext consists of two parts:
// (1) the IV used for encryption and (2) the actual ciphertext.
//
// Note: AES-GCM implementation of crypto library always returns ciphertext with
// 128-bit tag.
func (a *AesGcm) Encrypt(pt []byte, aad []byte) ([]byte, error) {
	// Although Seal() function already checks for plaintext length,
	// this check is repeated here to avoid panic.
	if uint64(len(pt)) > (1<<36)-32 {
		return nil, fmt.Errorf("aes_gcm: plaintext too long")
	}
	cipher, err := a.newCipher(a.Key)
	if err != nil {
		return nil, err
	}
	iv := a.newIV()
	ct := cipher.Seal(nil, iv, pt, aad)
	var ret []byte
	ret = append(ret, iv...)
	ret = append(ret, ct...)
	return ret, nil
}

// Decrypt decrypts {@code ct} with {@code aad} as the additionalauthenticated data.
func (a *AesGcm) Decrypt(ct []byte, aad []byte) ([]byte, error) {
	if len(ct) < AES_GCM_IV_SIZE+AES_GCM_TAG_SIZE {
		return nil, fmt.Errorf("aes_gcm: ciphertext too short")
	}
	cipher, err := a.newCipher(a.Key)
	if err != nil {
		return nil, err
	}
	iv := ct[:AES_GCM_IV_SIZE]
	pt, err := cipher.Open(nil, iv, ct[AES_GCM_IV_SIZE:], aad)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm: %s", err)
	}
	return pt, nil
}

// newIV creates a new IV for encryption.
func (a *AesGcm) newIV() []byte {
	return random.GetRandomBytes(AES_GCM_IV_SIZE)
}

var errCipher = fmt.Errorf("aes_gcm: initializing cipher failed")

// newCipher creates a new AES-GCM cipher using the given key and the crypto library.
func (a *AesGcm) newCipher(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errCipher
	}
	ret, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errCipher
	}
	return ret, nil
}
