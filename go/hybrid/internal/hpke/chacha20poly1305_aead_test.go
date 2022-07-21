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

func TestChaCha20Poly1305AEADSealOpen(t *testing.T) {
	i := 0
	vecs := aeadRFCVectors(t)
	for k, v := range vecs {
		if k.aeadID != chaCha20Poly1305 {
			continue
		}

		i++
		t.Run(fmt.Sprintf("%d", k.id), func(t *testing.T) {
			aead, err := newAEAD(k.aeadID)
			if err != nil {
				t.Fatalf("newAEAD(%d) err = %v, want nil", k.aeadID, err)
			}

			ciphertext, err := aead.seal(v.key, v.nonce, v.plaintext, v.associatedData)
			if err != nil {
				t.Fatalf("seal err = %v, want nil", err)
			}
			if !bytes.Equal(ciphertext, v.ciphertext) {
				t.Errorf("seal = %x, want %x", ciphertext, v.ciphertext)
			}

			plaintext, err := aead.open(v.key, v.nonce, v.ciphertext, v.associatedData)
			if err != nil {
				t.Fatalf("open err = %v, want nil", err)
			}
			if !bytes.Equal(plaintext, v.plaintext) {
				t.Errorf("open = %x, want %x", plaintext, v.plaintext)
			}
		})
	}
	if i < 2 {
		t.Errorf("number of vectors tested = %d, want > %d", i, 2)
	}
}
