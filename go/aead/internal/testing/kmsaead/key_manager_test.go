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

package kmsaead_test

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/internal/testing/kmsaead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testing/fakekms"
)

// The fake KMS should only be used in tests. It is not secure.
const keyURI = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"

func TestCreateEncryptDecrypt(t *testing.T) {
	registry.RegisterKeyManager(kmsaead.NewKeyManager())

	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatalf("fakekms.NewClient(keyURI) err = %q, want nil", err)
	}
	registry.RegisterKMSClient(client)

	template, err := kmsaead.CreateKeyTemplate(keyURI)
	if err != nil {
		t.Fatalf("kmsaead.CreateKeyTemplate(keyURI) err = %q, want nil", err)
	}
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(template) err = %q, want nil", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %q, want nil", err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")

	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Encrypt(plaintext, associatedData) err = %q, want nil", err)
	}

	gotPlaintext, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("gotPlaintext = %q, want %q", gotPlaintext, plaintext)
	}

	_, err = primitive.Decrypt(ciphertext, []byte("invalidAssociatedData"))
	if err == nil {
		t.Fatalf("primitive.Decrypt(ciphertext, []byte(\"invalidAssociatedData\")) err = nil, want error")
	}

	// Verify that the AEAD primitive returned by client is also able to decrypt.
	primitive2, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) err = %q, want nil", err)
	}
	gotPlaintext2, err := primitive2.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("primitive2.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext2, plaintext) {
		t.Fatalf("gotPlaintext2 = %q, want %q", gotPlaintext, plaintext)
	}
}
