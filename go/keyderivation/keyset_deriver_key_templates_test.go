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

package keyderivation_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyderivation/internal/streamingprf"
	"github.com/google/tink/go/keyderivation"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestPRFBasedKeyTemplateDerivesAESGCMKeyset(t *testing.T) {
	plaintext := random.GetRandomBytes(16)
	associatedData := random.GetRandomBytes(8)
	prfs := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "HKDF-SHA256",
			template: streamingprf.HKDFSHA256RawKeyTemplate(),
		},
		{
			name:     "HKDF-SHA512",
			template: streamingprf.HKDFSHA512RawKeyTemplate(),
		},
	}
	derivations := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128GCM",
			template: aead.AES128GCMKeyTemplate(),
		},
		{
			name:     "AES256GCM",
			template: aead.AES256GCMKeyTemplate(),
		},
		{
			name:     "AES256GCMNoPrefix",
			template: aead.AES256GCMNoPrefixKeyTemplate(),
		},
	}
	for _, prf := range prfs {
		for _, der := range derivations {
			for _, salt := range [][]byte{nil, []byte("salt")} {
				name := fmt.Sprintf("%s_%s", prf.name, der.name)
				if salt != nil {
					name += "_with_salt"
				}
				t.Run(name, func(t *testing.T) {
					template, err := keyderivation.CreatePRFBasedKeyTemplate(prf.template, der.template)
					if err != nil {
						t.Fatalf("CreatePRFBasedKeyTemplate() err = %v, want nil", err)
					}
					handle, err := keyset.NewHandle(template)
					if err != nil {
						t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
					}
					d, err := keyderivation.New(handle)
					if err != nil {
						t.Fatalf("keyderivation.New() err = %v, want nil", err)
					}
					derivedHandle, err := d.DeriveKeyset(salt)
					if err != nil {
						t.Fatalf("DeriveKeyset() err = %v, want nil", err)
					}
					a, err := aead.New(derivedHandle)
					if err != nil {
						t.Fatalf("aead.New() err = %v, want nil", err)
					}
					ciphertext, err := a.Encrypt(plaintext, associatedData)
					if err != nil {
						t.Fatalf("Encrypt() err = %v, want nil", err)
					}
					gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
					if err != nil {
						t.Fatalf("Decrypt() err = %v, want nil", err)
					}
					if !bytes.Equal(gotPlaintext, plaintext) {
						t.Errorf("Decrypt() = %v, want %v", gotPlaintext, plaintext)
					}
				})
			}
		}
	}
}

func TestInvalidPRFBasedDeriverKeyTemplates(t *testing.T) {
	for _, test := range []struct {
		name               string
		prfKeyTemplate     *tinkpb.KeyTemplate
		derivedKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name: "nil templates",
		},
		{
			name:               "nil PRF key template",
			derivedKeyTemplate: aead.AES128GCMKeyTemplate(),
		},
		{
			name:           "nil derived key template",
			prfKeyTemplate: streamingprf.HKDFSHA256RawKeyTemplate(),
		},
		{
			name:               "malformed PRF key template",
			prfKeyTemplate:     &tinkpb.KeyTemplate{TypeUrl: "\xff"},
			derivedKeyTemplate: aead.AES128GCMKeyTemplate(),
		},
		// AES128CTRHMACSHA256KeyTemplate() is an unsupported derived key template
		// because DeriveKey() is not implemented in the AES-CTR-HMAC key manager.
		// TODO(b/227682336): Add mock key manager that doesn't derive keys.
		{
			name:               "unsupported templates",
			prfKeyTemplate:     aead.AES128GCMKeyTemplate(),
			derivedKeyTemplate: aead.AES128CTRHMACSHA256KeyTemplate()},
		{
			name:               "unsupported PRF key template",
			prfKeyTemplate:     aead.AES128GCMKeyTemplate(),
			derivedKeyTemplate: aead.AES128GCMKeyTemplate(),
		},
		{
			name:               "unsupported derived key template",
			prfKeyTemplate:     streamingprf.HKDFSHA256RawKeyTemplate(),
			derivedKeyTemplate: aead.AES128CTRHMACSHA256KeyTemplate(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := keyderivation.CreatePRFBasedKeyTemplate(test.prfKeyTemplate, test.derivedKeyTemplate); err == nil {
				t.Error("CreatePRFBasedKeyTemplate() err = nil, want non-nil")
			}
		})
	}
}
