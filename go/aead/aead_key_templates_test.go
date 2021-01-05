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
	"bytes"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testing/fakekms"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeyTemplates(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128_GCM",
			template: aead.AES128GCMKeyTemplate(),
		}, {
			name:     "AES256_GCM",
			template: aead.AES256GCMKeyTemplate(),
		}, {
			name:     "AES128_CTR_HMAC_SHA256",
			template: aead.AES128CTRHMACSHA256KeyTemplate(),
		}, {
			name:     "AES256_CTR_HMAC_SHA256",
			template: aead.AES256CTRHMACSHA256KeyTemplate(),
		}, {
			name:     "CHACHA20_POLY1305",
			template: aead.ChaCha20Poly1305KeyTemplate(),
		}, {
			name:     "XCHACHA20_POLY1305",
			template: aead.XChaCha20Poly1305KeyTemplate(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := testutil.KeyTemplateProto("aead", tc.name)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if !proto.Equal(want, tc.template) {
				t.Errorf("template %s is not equal to '%s'", tc.name, tc.template)
			}
			if err := testEncryptDecrypt(tc.template); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestNoPrefixKeyTemplates(t *testing.T) {
	testutil.SkipTestIfTestSrcDirIsNotSet(t)
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES256_GCM",
			template: aead.AES256GCMNoPrefixKeyTemplate(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := testutil.KeyTemplateProto("aead", tc.name)
			if err != nil {
				t.Fatalf("testutil.KeyTemplateProto('aead', tc.name) failed: %s", err)
			}
			want.OutputPrefixType = tinkpb.OutputPrefixType_RAW
			if !proto.Equal(want, tc.template) {
				t.Errorf("template %s is not equal to '%s'", tc.name, tc.template)
			}
			if err := testEncryptDecrypt(tc.template); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestKMSEnvelopeAEADKeyTemplates(t *testing.T) {
	fakeKmsClient, err := fakekms.NewClient("fake-kms://")
	if err != nil {
		t.Fatalf("fakekms.NewClient('fake-kms://') failed: %v", err)
	}
	registry.RegisterKMSClient(fakeKmsClient)

	fixedKeyURI := "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"
	newKeyURI, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatalf("fakekms.NewKeyURI() failed: %v", err)
	}
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "Fixed Fake KMS Envelope AEAD Key with AES128_GCM",
			template: aead.KMSEnvelopeAEADKeyTemplate(fixedKeyURI, aead.AES128GCMKeyTemplate()),
		}, {
			name:     "New Fake KMS Envelope AEAD Key with AES128_GCM",
			template: aead.KMSEnvelopeAEADKeyTemplate(newKeyURI, aead.AES128GCMKeyTemplate()),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := testEncryptDecrypt(tc.template); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func testEncryptDecrypt(template *tinkpb.KeyTemplate) error {
	handle, err := keyset.NewHandle(template)
	if err != nil {
		return fmt.Errorf("keyset.NewHandle(template) failed: %v", err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		return fmt.Errorf("aead.New(handle) failed: %v", err)
	}

	var testInputs = []struct {
		plaintext []byte
		aad1      []byte
		aad2      []byte
	}{
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      []byte(""),
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: []byte(""),
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: nil,
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		}, {
			plaintext: nil,
			aad1:      []byte(""),
			aad2:      []byte(""),
		}, {
			plaintext: nil,
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      nil,
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      []byte(""),
		},
	}
	for _, ti := range testInputs {
		ciphertext, err := primitive.Encrypt(ti.plaintext, ti.aad1)
		if err != nil {
			return fmt.Errorf("encryption failed, error: %v", err)
		}
		decrypted, err := primitive.Decrypt(ciphertext, ti.aad2)
		if err != nil {
			return fmt.Errorf("decryption failed, error: %v", err)
		}
		if !bytes.Equal(ti.plaintext, decrypted) {
			return fmt.Errorf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, ti.plaintext)
		}
	}
	return nil
}
