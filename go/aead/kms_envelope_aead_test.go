// Copyright 2019 Google LLC
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

package aead_test

import (
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

func createKMSEnvelopeAEAD(t *testing.T) tink.AEAD {
	t.Helper()

	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to create new handle: %v", err)
	}

	parentAEAD, err := aead.New(kh)
	if err != nil {
		t.Fatalf("failed to create parent AEAD: %v", err)
	}

	return aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), parentAEAD)
}

func TestKMSEnvelopeRoundtrip(t *testing.T) {
	a := createKMSEnvelopeAEAD(t)

	originalPlaintext := "hello world"

	ciphertext, err := a.Encrypt([]byte(originalPlaintext), nil)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	plaintextBytes, err := a.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}
	plaintext := string(plaintextBytes)

	if plaintext != originalPlaintext {
		t.Errorf("Decrypt(Encrypt(%q)) = %q; want %q", originalPlaintext, plaintext, originalPlaintext)
	}
}

func TestKMSEnvelopeShortCiphertext(t *testing.T) {
	a := createKMSEnvelopeAEAD(t)

	_, err := a.Decrypt([]byte{1}, nil)
	if err == nil {
		t.Errorf("Decrypt({1}) worked, but should've errored out")
	}

}
