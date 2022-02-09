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
	"bytes"
	"fmt"
	"testing"
)

func TestAesGcmHpkeAeadSealOpen(t *testing.T) {
	vecs := hpkeAESGCMEncryptionVectors(t)
	for k, v := range vecs {
		t.Run(fmt.Sprintf("%d", k.aeadID), func(t *testing.T) {
			{
				var keyLength int
				switch k.aeadID {
				case aes128GCM:
					keyLength = 16
				case aes256GCM:
					keyLength = 32
				default:
					t.Fatalf("unsupported AEAD ID %d", k.aeadID)
				}
				a, err := newAesGcmHpkeAead(keyLength)
				if err != nil {
					t.Fatalf("newAesGcmHpkeAead(%d): got err %q, want success", keyLength, err)
				}

				ct, err := a.seal(v.key, v.nonce, v.plaintext, v.associatedData)
				if err != nil {
					t.Fatalf("seal: got err %q, want success", err)
				}
				if !bytes.Equal(ct, v.ciphertext) {
					t.Errorf("seal: got %x, want %x", ct, v.ciphertext)
				}

				pt, err := a.open(v.key, v.nonce, v.ciphertext, v.associatedData)
				if err != nil {
					t.Fatalf("open: got err %q, want success", err)
				}
				if !bytes.Equal(pt, v.plaintext) {
					t.Errorf("open: got %x, want %x", pt, v.plaintext)
				}
			}

			// Test exactly as above, except instantiate aesGcmHpkeAead with a key
			// length that does not match the length of the key passed into seal and
			// open.
			{
				var wrongKeyLength int
				switch k.aeadID {
				case aes128GCM:
					wrongKeyLength = 32
				case aes256GCM:
					wrongKeyLength = 16
				default:
					t.Fatalf("unsupported AEAD ID %d", k.aeadID)
				}
				a, err := newAesGcmHpkeAead(wrongKeyLength)
				if err != nil {
					t.Fatalf("newAesGcmHpkeAead(%d): got err %q, want success", wrongKeyLength, err)
				}

				if _, err := a.seal(v.key, v.nonce, v.plaintext, v.associatedData); err == nil {
					t.Error("seal with unexpected key length: got success, want err")
				}
				if _, err := a.open(v.key, v.nonce, v.ciphertext, v.associatedData); err == nil {
					t.Error("open with unexpected key length: got success, want err")
				}
			}
		})
	}
}

func TestAesGcmHpkeAeadUnsupportedKeyLength(t *testing.T) {
	if _, err := newAesGcmHpkeAead(24); err == nil {
		t.Error("newAesGcmHpkeAead with unsupported key length: got success, want err")
	}
}
