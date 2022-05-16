// Copyright 2022 Google LLC
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

package aead

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const poly1305TagSize = 16

// ChaCha20Poly1305InsecureNonce is an insecure implementation of the AEAD
// interface that permits the user to set the nonce.
type ChaCha20Poly1305InsecureNonce struct {
	Key []byte
}

// NewChaCha20Poly1305InsecureNonce returns a ChaCha20Poly1305InsecureNonce instance.
// The key argument should be a 32-bytes key.
func NewChaCha20Poly1305InsecureNonce(key []byte) (*ChaCha20Poly1305InsecureNonce, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("bad key length")
	}

	return &ChaCha20Poly1305InsecureNonce{Key: key}, nil
}

// Encrypt encrypts plaintext with nonce and associatedData.
func (ca *ChaCha20Poly1305InsecureNonce) Encrypt(nonce, plaintext, associatedData []byte) ([]byte, error) {
	if len(plaintext) > maxInt-chacha20poly1305.NonceSize-poly1305TagSize {
		return nil, fmt.Errorf("plaintext too long")
	}
	c, err := chacha20poly1305.New(ca.Key)
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, nonce, plaintext, associatedData), nil
}

// Decrypt decrypts ciphertext with nonce and associatedData.
func (ca *ChaCha20Poly1305InsecureNonce) Decrypt(nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("bad nonce length")
	}
	if len(ciphertext) < poly1305TagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	c, err := chacha20poly1305.New(ca.Key)
	if err != nil {
		return nil, err
	}
	return c.Open(nil, nonce, ciphertext, associatedData)
}
