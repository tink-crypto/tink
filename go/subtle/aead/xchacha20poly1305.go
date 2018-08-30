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

// Package aead provides subtle implementations of the Aead primitive.
package aead

import (
	"errors"
	"fmt"

	"google3/third_party/golang/go_crypto/chacha20poly1305/chacha20poly1305"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

// XChacha20poly1305Aead is an implementation of Aead interface.
type XChacha20poly1305Aead struct {
	key []byte
}

// Assert that XChacha20poly1305Aead implements the Aead interface.
var _ tink.Aead = (*XChacha20poly1305Aead)(nil)

// NewXChacha20poly1305Aead returns an XChacha20poly1305Aead instance.
// The key argument should be a 32-bytes key.
func NewXChacha20poly1305Aead(key []byte) (*XChacha20poly1305Aead, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("xchacha20poly1305: bad key length")
	}

	return &XChacha20poly1305Aead{key: key}, nil
}

// Encrypt encrypts {@code pt} with {@code aad} as additional
// authenticated data. The resulting ciphertext consists of two parts:
// (1) the nonce used for encryption and (2) the actual ciphertext.
func (x *XChacha20poly1305Aead) Encrypt(pt []byte, aad []byte) ([]byte, error) {
	c, err := chacha20poly1305.NewX(x.key)
	if err != nil {
		return nil, err
	}

	n := x.newNonce()
	ct := c.Seal(nil, n, pt, aad)
	var ret []byte
	ret = append(ret, n...)
	ret = append(ret, ct...)
	return ret, nil
}

// Decrypt decrypts {@code ct} with {@code aad} as the additionalauthenticated data.
func (x *XChacha20poly1305Aead) Decrypt(ct []byte, aad []byte) ([]byte, error) {
	c, err := chacha20poly1305.NewX(x.key)
	if err != nil {
		return nil, err
	}

	n := ct[:chacha20poly1305.NonceSizeX]
	pt, err := c.Open(nil, n, ct[chacha20poly1305.NonceSizeX:], aad)
	if err != nil {
		return nil, fmt.Errorf("XChacha20poly1305Aead.Decrypt: %s", err)
	}
	return pt, nil
}

// newNonce creates a new nonce for encryption.
func (x *XChacha20poly1305Aead) newNonce() []byte {
	return random.GetRandomBytes(chacha20poly1305.NonceSizeX)
}
