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
	prfs := []namedTemplate{
		{"HKDF-SHA256", streamingprf.HKDFSHA256RawKeyTemplate()},
		{"HKDF-SHA512", streamingprf.HKDFSHA512RawKeyTemplate()},
	}
	derivations := []namedTemplate{
		{"AES128GCM", aead.AES128GCMKeyTemplate()},
		{"AES256GCM", aead.AES256GCMKeyTemplate()},
		{"AES256GCMNoPrefix", aead.AES256GCMNoPrefixKeyTemplate()},
	}
	for _, prf := range prfs {
		for _, der := range derivations {
			for _, salt := range [][]byte{nil, []byte("salt")} {
				name := fmt.Sprintf("%s/%s", prf.name, der.name)
				if salt != nil {
					name += "/salt"
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
		{"nil everything", nil, nil},
		{"nil PRF key template", nil, aead.AES128GCMKeyTemplate()},
		{"nil derived key template", streamingprf.HKDFSHA256RawKeyTemplate(), nil},
		// AES128CTRHMACSHA256KeyTemplate() is an unsupported derived key template
		// because DeriveKey() is not implemented in the AES-CTR-HMAC key manager.
		// TODO(b/227682336): Add mock key manager that doesn't derive keys.
		{"unsupported everything", aead.AES128GCMKeyTemplate(), aead.AES128CTRHMACSHA256KeyTemplate()},
		{"unsupported PRF key template", aead.AES128GCMKeyTemplate(), aead.AES128GCMKeyTemplate()},
		{"unsupported derived key template", streamingprf.HKDFSHA256RawKeyTemplate(), aead.AES128CTRHMACSHA256KeyTemplate()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := keyderivation.CreatePRFBasedKeyTemplate(test.prfKeyTemplate, test.derivedKeyTemplate); err == nil {
				t.Error("CreatePRFBasedKeyTemplate() err = nil, want non-nil")
			}
		})
	}
}
