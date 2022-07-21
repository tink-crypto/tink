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

package hpke

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAESGCMAEADSealOpen(t *testing.T) {
	i := 0
	vecs := aeadRFCVectors(t)
	for k, v := range vecs {
		if k.aeadID != aes128GCM && k.aeadID != aes256GCM {
			continue
		}

		i++
		t.Run(fmt.Sprintf("%d", k.id), func(t *testing.T) {
			{
				aead, err := newAEAD(k.aeadID)
				if err != nil {
					t.Fatalf("newAEAD(%d): got err %q, want success", k.aeadID, err)
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
				var wrongID uint16
				switch k.aeadID {
				case aes128GCM:
					wrongID = aes256GCM
				case aes256GCM:
					wrongID = aes128GCM
				default:
					t.Fatalf("AEAD ID %d is not supported", k.aeadID)
				}
				aead, err := newAEAD(wrongID)
				if err != nil {
					t.Fatalf("newAEAD(%d): got err %q, want success", wrongID, err)
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
	if i < 2 {
		t.Errorf("number of vectors tested = %d, want > %d", i, 2)
	}
}
