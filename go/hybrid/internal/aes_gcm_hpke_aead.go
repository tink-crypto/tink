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

package internal

import (
	"fmt"

	"github.com/google/tink/go/aead/subtle"
)

// aesGcmHpkeAead is an AES GCM HPKE AEAD variant that implements interface
// hpkeAead.
var _ hpkeAead = (*aesGcmHpkeAead)(nil)

type aesGcmHpkeAead struct {
	// HPKE AEAD algorithm identifier.
	id        uint16
	keyLength int
}

// newAesGcmHpkeAead constructs an AES-GCM HPKE AEAD using keyLength.
func newAesGcmHpkeAead(keyLength int) (*aesGcmHpkeAead, error) {
	var id uint16
	if keyLength == 16 {
		id = aes128GCM
	} else if keyLength == 32 {
		id = aes256GCM
	} else {
		return nil, fmt.Errorf("key length %d is not supported", keyLength)
	}
	return &aesGcmHpkeAead{
		id:        id,
		keyLength: keyLength,
	}, nil
}

func (a *aesGcmHpkeAead) seal(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	if len(key) != a.keyLength {
		return nil, fmt.Errorf("unexpected key length: got %d, want %d", len(key), a.keyLength)
	}
	i, err := subtle.NewInsecureIvAesGcm(key, false /*=prependIv*/)
	if err != nil {
		return nil, fmt.Errorf("NewInsecureIvAesGcm: %q", err)
	}
	return i.Encrypt(nonce, plaintext, associatedData)
}

func (a *aesGcmHpkeAead) open(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	if len(key) != a.keyLength {
		return nil, fmt.Errorf("unexpected key length: got %d, want %d", len(key), a.keyLength)
	}
	i, err := subtle.NewInsecureIvAesGcm(key, false /*=prependIv*/)
	if err != nil {
		return nil, fmt.Errorf("NewInsecureIvAesGcm: %q", err)
	}
	return i.Decrypt(nonce, ciphertext, associatedData)
}

func (a *aesGcmHpkeAead) aeadID() uint16 {
	return a.id
}
