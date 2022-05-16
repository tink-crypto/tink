// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package subtle

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	internalaead "github.com/google/tink/go/internal/aead"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

const (
	poly1305TagSize = 16
)

// ChaCha20Poly1305 is an implementation of AEAD interface.
type ChaCha20Poly1305 struct {
	Key                           []byte
	chaCha20Poly1305InsecureNonce *internalaead.ChaCha20Poly1305InsecureNonce
}

// Assert that ChaCha20Poly1305 implements the AEAD interface.
var _ tink.AEAD = (*ChaCha20Poly1305)(nil)

// NewChaCha20Poly1305 returns an ChaCha20Poly1305 instance.
// The key argument should be a 32-bytes key.
func NewChaCha20Poly1305(key []byte) (*ChaCha20Poly1305, error) {
	chaCha20Poly1305InsecureNonce, err := internalaead.NewChaCha20Poly1305InsecureNonce(key)
	return &ChaCha20Poly1305{
		Key:                           key,
		chaCha20Poly1305InsecureNonce: chaCha20Poly1305InsecureNonce,
	}, err
}

// Encrypt encrypts plaintext with associatedData.
// The resulting ciphertext consists of two parts:
// (1) the nonce used for encryption and (2) the actual ciphertext.
func (ca *ChaCha20Poly1305) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	nonce := random.GetRandomBytes(chacha20poly1305.NonceSize)
	ct, err := ca.chaCha20Poly1305InsecureNonce.Encrypt(nonce, plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// Decrypt decrypts ciphertext with associatedData.
func (ca *ChaCha20Poly1305) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.NonceSize+poly1305TagSize {
		return nil, fmt.Errorf("chacha20poly1305: ciphertext too short")
	}
	nonce := ciphertext[:chacha20poly1305.NonceSize]
	return ca.chaCha20Poly1305InsecureNonce.Decrypt(nonce, ciphertext[chacha20poly1305.NonceSize:], associatedData)
}
