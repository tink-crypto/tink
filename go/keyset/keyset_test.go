// Copyright 2023 Google LLC
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

package keyset_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testing/fakekms"
)

const keyURI = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"

func TestKMSEncryptedKeysetHandle(t *testing.T) {
	// We use a fake KMS to avoid making RPCs.
	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatalf("fakekms.NewClient(keyURI) failed: %v", err)
	}
	keyEncryptionAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a new keyset handle for the primitive we want to use.
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt the keyset handle using the KMS AEAD.
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = handle.Write(writer, keyEncryptionAEAD)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKeyset := buf.Bytes()

	// Use the keyset handle.
	a, err := aead.New(handle)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatal(err)
	}

	// Get the keyset handle from the encrypted keyset and the KMS.
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	handle2, err := keyset.Read(reader, keyEncryptionAEAD)
	if err != nil {
		t.Fatal(err)
	}

	// Use the keyset handle2.
	a2, err := aead.New(handle2)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := a2.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(decrypted, plaintext) {
		t.Errorf("got = %v, want = %v", decrypted, plaintext)
	}
}
