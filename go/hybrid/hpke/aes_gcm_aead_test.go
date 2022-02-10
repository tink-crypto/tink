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

func TestAESGCMAEADSealOpen(t *testing.T) {
	vecs := aesGCMEncryptionVectors(t)
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
				aead, err := newAESGCMAEAD(keyLength)
				if err != nil {
					t.Fatalf("newAESGCMAEAD(%d): got err %q, want success", keyLength, err)
				}

				ciphertext, err := aead.seal(v.key, v.nonce, v.plaintext, v.associatedData)
				if err != nil {
					t.Fatalf("seal: got err %q, want success", err)
				}
				if !bytes.Equal(ciphertext, v.ciphertext) {
					t.Errorf("seal: got %x, want %x", ciphertext, v.ciphertext)
				}

				plaintext, err := aead.open(v.key, v.nonce, v.ciphertext, v.associatedData)
				if err != nil {
					t.Fatalf("open: got err %q, want success", err)
				}
				if !bytes.Equal(plaintext, v.plaintext) {
					t.Errorf("open: got %x, want %x", plaintext, v.plaintext)
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
				aead, err := newAESGCMAEAD(wrongKeyLength)
				if err != nil {
					t.Fatalf("newAESGCMAEAD(%d): got err %q, want success", wrongKeyLength, err)
				}

				if _, err := aead.seal(v.key, v.nonce, v.plaintext, v.associatedData); err == nil {
					t.Error("seal with unexpected key length: got success, want err")
				}
				if _, err := aead.open(v.key, v.nonce, v.ciphertext, v.associatedData); err == nil {
					t.Error("open with unexpected key length: got success, want err")
				}
			}
		})
	}
}

func TestAESGCMAEADUnsupportedKeyLength(t *testing.T) {
	if _, err := newAESGCMAEAD(24); err == nil {
		t.Error("newAESGCMAEAD with unsupported key length: got success, want err")
	}
}

func TestAESGCMAEADID(t *testing.T) {
	aead, err := newAESGCMAEAD(16)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := aead.id(), aes128GCM; got != want {
		t.Errorf("id: got %d, want %d", got, want)
	}

	aead, err = newAESGCMAEAD(32)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := aead.id(), aes256GCM; got != want {
		t.Errorf("id: got %d, want %d", got, want)
	}
}
