// Copyright 2021 Google LLC
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

package hybrid

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type eciesAEADHKDFDEMHelperTestCase struct {
	name     string
	template *tinkpb.KeyTemplate
	keySize  uint32
}

var (
	eciesAEADHKDFDEMHelperSupportedAEADs = []eciesAEADHKDFDEMHelperTestCase{
		{
			name:     "AESCTRHMACSHA256",
			template: aead.AES256CTRHMACSHA256KeyTemplate(),
			keySize:  64,
		},
		{
			name:     "AES128CTRHMACSHA256",
			template: aead.AES128CTRHMACSHA256KeyTemplate(),
			keySize:  48,
		},
		{
			name:     "AES256GCM",
			template: aead.AES256GCMKeyTemplate(),
			keySize:  32,
		},
		{
			name:     "AES128GCM",
			template: aead.AES128GCMKeyTemplate(),
			keySize:  16,
		},
	}

	eciesAEADHKDFDEMHelperSupportedDAEADs = []eciesAEADHKDFDEMHelperTestCase{
		{
			name:     "AESSIV",
			template: daead.AESSIVKeyTemplate(),
			keySize:  64,
		},
	}
)

func TestECIESAEADHKDFDEMHelper_AEADKeyTemplates(t *testing.T) {
	plaintext := random.GetRandomBytes(20)
	associatedData := random.GetRandomBytes(20)

	for _, tc := range eciesAEADHKDFDEMHelperSupportedAEADs {
		t.Run(tc.name, func(t *testing.T) {
			dem, err := newRegisterECIESAEADHKDFDemHelper(tc.template)
			if err != nil {
				t.Fatalf("newRegisterECIESAEADHKDFDEMHelper(tc.template) err = %s, want nil", err)
			}

			sk := random.GetRandomBytes(dem.GetSymmetricKeySize())
			primitive, err := dem.GetAEADOrDAEAD(sk)
			if err != nil {
				t.Fatalf("dem.GetAEADorDAEAD(sk) err = %v, want nil", err)
			}
			a, ok := primitive.(tink.AEAD)
			if !ok {
				t.Fatalf("primitive is not of type tink.AEAD")
			}

			var ciphertext []byte
			ciphertext, err = a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt() err = %v, want nil", err)
			}

			var decrypted []byte
			decrypted, err = a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt() err = %v, want nil", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("a.Decrypt() = %x, want: %x", decrypted, plaintext)
			}
		})
	}
}

func TestECIESAEADHKDFDEMHelper_DAEADKeyTemplates(t *testing.T) {
	plaintext := random.GetRandomBytes(20)
	associatedData := random.GetRandomBytes(20)

	for _, tc := range eciesAEADHKDFDEMHelperSupportedDAEADs {
		t.Run(tc.name, func(t *testing.T) {
			dem, err := newRegisterECIESAEADHKDFDemHelper(tc.template)
			if err != nil {
				t.Fatalf("newRegisterECIESAEADHKDFDEMHelper(tc.template) err = %s, want nil", err)
			}

			sk := random.GetRandomBytes(dem.GetSymmetricKeySize())
			primitive, err := dem.GetAEADOrDAEAD(sk)
			if err != nil {
				t.Fatalf("dem.GetAEADorDAEAD(sk) err = %v, want nil", err)
			}
			d, ok := primitive.(tink.DeterministicAEAD)
			if !ok {
				t.Fatalf("primitive is not of type tink.DeterministicAEAD")
			}

			var ciphertext []byte
			ciphertext, err = d.EncryptDeterministically(plaintext, associatedData)
			if err != nil {
				t.Fatalf("d.Encrypt() err = %v, want nil", err)
			}

			var decrypted []byte
			decrypted, err = d.DecryptDeterministically(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("d.Decrypt() err = %v, want nil", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("d.Decrypt() = %x, want: %x", decrypted, plaintext)
			}
		})
	}
}

func TestECIESAEADHKDFDEMHelper_KeySizes(t *testing.T) {
	var testCases []eciesAEADHKDFDEMHelperTestCase
	testCases = append(testCases, eciesAEADHKDFDEMHelperSupportedAEADs...)
	testCases = append(testCases, eciesAEADHKDFDEMHelperSupportedDAEADs...)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dem, err := newRegisterECIESAEADHKDFDemHelper(tc.template)
			if err != nil {
				t.Fatalf("newRegisterECIESAEADHKDFDemHelper(tc.template): %s", err)
			}
			if dem.GetSymmetricKeySize() != tc.keySize {
				t.Errorf("dem.GetSymmetricKeySize() = %d, want: %d", dem.GetSymmetricKeySize(), tc.keySize)
			}

			shortKey := make([]byte, tc.keySize-1)
			if _, err = dem.GetAEADOrDAEAD(shortKey); err == nil {
				t.Errorf("dem.GetAEADOrDAEAD(shortKey) err = nil, want non-nil")
			}

			longKey := make([]byte, tc.keySize+1)
			if _, err = dem.GetAEADOrDAEAD(longKey); err == nil {
				t.Errorf("dem.GetAEADOrDAEAD(longKey) err = nil, want non-nil")
			}
		})
	}
}

func TestECIESAEADHKDFDEMHelper_UnsupportedKeyTemplates(t *testing.T) {
	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "signature",
			template: signature.ECDSAP256KeyTemplate(),
		},
		{
			name:     "mac",
			template: mac.HMACSHA256Tag256KeyTemplate(),
		},
		{
			name:     "invalid_type_and_value",
			template: &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}},
		},
		{
			name:     "aesctrhmac_empty_value",
			template: &tinkpb.KeyTemplate{TypeUrl: aesCTRHMACAEADTypeURL},
		},
		{
			name:     "aesgcm_empty_value",
			template: &tinkpb.KeyTemplate{TypeUrl: aesGCMTypeURL},
		},
		{
			name:     "aessiv_empty_value",
			template: &tinkpb.KeyTemplate{TypeUrl: aesSIVTypeURL},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newRegisterECIESAEADHKDFDemHelper(tc.template); err == nil {
				t.Errorf("newRegisterECIESAEADHKDFDemHelper() err = nil, want non-nil")
			}
		})
	}
}
