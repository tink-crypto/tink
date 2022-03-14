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
///////////////////////////////////////////////////////////////////////////////

package hpke

import (
	"fmt"

	internalaead "github.com/google/tink/go/internal/aead"
)

// aesGCMAEAD is an AES GCM HPKE AEAD variant that implements interface
// aead.
type aesGCMAEAD struct {
	// HPKE AEAD algorithm identifier.
	aeadID uint16
	keyLen int
}

var _ aead = (*aesGCMAEAD)(nil)

// newAESGCMAEAD constructs an AES-GCM HPKE AEAD using keyLength.
func newAESGCMAEAD(keyLength int) (*aesGCMAEAD, error) {
	switch keyLength {
	case 16:
		return &aesGCMAEAD{aeadID: aes128GCM, keyLen: 16}, nil
	case 32:
		return &aesGCMAEAD{aeadID: aes256GCM, keyLen: 32}, nil
	default:
		return nil, fmt.Errorf("key length %d is not supported", keyLength)
	}
}

func (a *aesGCMAEAD) seal(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	if len(key) != a.keyLen {
		return nil, fmt.Errorf("unexpected key length: got %d, want %d", len(key), a.keyLen)
	}
	i, err := internalaead.NewAESGCMInsecureIV(key, false /*=prependIV*/)
	if err != nil {
		return nil, fmt.Errorf("NewAESGCMInsecureIV: %v", err)
	}
	return i.Encrypt(nonce, plaintext, associatedData)
}

func (a *aesGCMAEAD) open(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if len(key) != a.keyLen {
		return nil, fmt.Errorf("unexpected key length: got %d, want %d", len(key), a.keyLen)
	}
	i, err := internalaead.NewAESGCMInsecureIV(key, false /*=prependIV*/)
	if err != nil {
		return nil, fmt.Errorf("NewAESGCMInsecureIV: %v", err)
	}
	return i.Decrypt(nonce, ciphertext, associatedData)
}

func (a *aesGCMAEAD) id() uint16 {
	return a.aeadID
}

func (a *aesGCMAEAD) keyLength() int {
	return a.keyLen
}

func (a *aesGCMAEAD) nonceLength() int {
	return internalaead.AESGCMIVSize
}
