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

package aead_test

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/testing/fakekms"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKMSEnvelopeWorksWithTinkKeyTemplatesAsDekTemplate(t *testing.T) {
	keyURI := "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"
	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatal(err)
	}
	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	invalidAssociatedData := []byte("invalidAssociatedData")

	var kmsEnvelopeAeadDekTestCases = []struct {
		name        string
		dekTemplate *tinkpb.KeyTemplate
	}{
		{
			name:        "AES128_GCM",
			dekTemplate: aead.AES128GCMKeyTemplate(),
		}, {
			name:        "AES256_GCM",
			dekTemplate: aead.AES256GCMKeyTemplate(),
		}, {
			name:        "AES256_GCM_NO_PREFIX",
			dekTemplate: aead.AES256GCMNoPrefixKeyTemplate(),
		}, {
			name:        "AES128_GCM_SIV",
			dekTemplate: aead.AES128GCMSIVKeyTemplate(),
		}, {
			name:        "AES256_GCM_SIV",
			dekTemplate: aead.AES256GCMSIVKeyTemplate(),
		}, {
			name:        "AES256_GCM_SIV_NO_PREFIX",
			dekTemplate: aead.AES256GCMSIVNoPrefixKeyTemplate(),
		}, {
			name:        "AES128_CTR_HMAC_SHA256",
			dekTemplate: aead.AES128CTRHMACSHA256KeyTemplate(),
		}, {
			name:        "AES256_CTR_HMAC_SHA256",
			dekTemplate: aead.AES256CTRHMACSHA256KeyTemplate(),
		}, {
			name:        "CHACHA20_POLY1305",
			dekTemplate: aead.ChaCha20Poly1305KeyTemplate(),
		}, {
			name:        "XCHACHA20_POLY1305",
			dekTemplate: aead.XChaCha20Poly1305KeyTemplate(),
		},
	}
	for _, tc := range kmsEnvelopeAeadDekTestCases {
		t.Run(tc.name, func(t *testing.T) {
			a := aead.NewKMSEnvelopeAEAD2(tc.dekTemplate, kekAEAD)
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
			}
			gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
			}
			if !bytes.Equal(gotPlaintext, plaintext) {
				t.Fatalf("got plaintext %q, want %q", gotPlaintext, plaintext)
			}
			if _, err = a.Decrypt(ciphertext, invalidAssociatedData); err == nil {
				t.Error("a.Decrypt(ciphertext, invalidAssociatedData) err = nil, want error")
			}
		})
	}
}

func TestKMSEnvelopeWithKmsEnvelopeKeyTemplatesAsDekTemplate_fails(t *testing.T) {
	keyURI := "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"
	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatalf("fakekms.NewClient(keyURI) err = %q, want nil", err)
	}
	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) err = %q, want nil", err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")

	// Use a KmsEnvelopeAeadKeyTemplate as DEK template.
	dekTemplate, err := aead.CreateKMSEnvelopeAEADKeyTemplate(keyURI, aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("aead.CreateKMSEnvelopAEADKeyTemplate() err = %q, want nil", err)
	}

	a := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
	_, err = a.Encrypt(plaintext, associatedData)
	if err == nil {
		t.Error("a.Encrypt(plaintext, associatedData) err = nil, want error")
	}
}

func TestKMSEnvelopeShortCiphertext(t *testing.T) {
	keyURI := "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"
	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		t.Fatal(err)
	}
	kekAEAD, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatal(err)
	}
	a := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kekAEAD)
	if _, err = a.Decrypt([]byte{1}, nil); err == nil {
		t.Error("a.Decrypt([]byte{1}, nil) err = nil, want error")
	}
}

type invalidAEAD struct {
}

func (a *invalidAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return []byte{}, nil
}

func (a *invalidAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return []byte{}, nil
}

func TestKMSEnvelopeEncryptWithInvalidAEADFails(t *testing.T) {
	invalidKEKAEAD := &invalidAEAD{}
	envAEADWithInvalidKEK := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), invalidKEKAEAD)

	if _, err := envAEADWithInvalidKEK.Encrypt([]byte("plaintext"), []byte("associatedData")); err == nil {
		t.Error("envAEADWithInvalidKEK.Encrypt(plaintext, associatedData) err = nil, want error")
	}
}
