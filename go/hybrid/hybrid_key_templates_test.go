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

package hybrid_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/internal/tinkerror"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	eciespb "github.com/google/tink/go/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func createECIESKeyTemplate(curveType commonpb.EllipticCurveType, hashType commonpb.HashType, dekTemplate *tinkpb.KeyTemplate) *tinkpb.KeyTemplate {
	format := &eciespb.EciesAeadHkdfKeyFormat{
		Params: &eciespb.EciesAeadHkdfParams{
			KemParams: &eciespb.EciesHkdfKemParams{
				CurveType:    curveType,
				HkdfHashType: hashType,
				HkdfSalt:     []byte{},
			},
			DemParams: &eciespb.EciesAeadDemParams{
				AeadDem: dekTemplate,
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          eciesAEADHKDFPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

func eciesP384AES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createECIESKeyTemplate(commonpb.EllipticCurveType_NIST_P384, commonpb.HashType_SHA384, aead.AES256GCMKeyTemplate())
}

func eciesP521AES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createECIESKeyTemplate(commonpb.EllipticCurveType_NIST_P521, commonpb.HashType_SHA512, aead.AES256GCMKeyTemplate())
}

func eciesP256AESSIVKeyTemplate() *tinkpb.KeyTemplate {
	return createECIESKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.HashType_SHA256, daead.AESSIVKeyTemplate())
}

func TestKeyTemplates(t *testing.T) {
	var testCases = []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
			template: hybrid.ECIESHKDFAES128GCMKeyTemplate(),
		},
		{
			name:     "ECIES_P384_HKDF_HMAC_SHA384_AES256_GCM",
			template: eciesP384AES256GCMKeyTemplate(),
		},
		{
			name:     "ECIES_P521_HKDF_HMAC_SHA512_AES256_GCM",
			template: eciesP521AES256GCMKeyTemplate(),
		},
		{
			name:     "ECIES_P256_AESSIV",
			template: eciesP256AESSIVKeyTemplate(),
		},
		{
			name:     "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
			template: hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate(),
		},
		{
			name:     "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
			template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template(),
		},
		{
			name:     "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
			template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template(),
		},
		{
			name:     "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
			template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template(),
		},
		{
			name:     "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
			template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template(),
		},
		{
			name:     "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
			template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template(),
		},
		{
			name:     "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW",
			template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateHandle, err := keyset.NewHandle(tc.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle(tc.template) failed: %s", err)
			}
			publicHandle, err := privateHandle.Public()
			if err != nil {
				t.Fatalf("privateHandle.Public() failed: %s", err)
			}
			enc, err := hybrid.NewHybridEncrypt(publicHandle)
			if err != nil {
				t.Fatalf("NewHybridEncrypt(publicHandle) err = %v, want nil", err)
			}
			dec, err := hybrid.NewHybridDecrypt(privateHandle)
			if err != nil {
				t.Fatalf("NewHybridDecrypt(privateHandle) err = %v, want nil", err)
			}
			var testInputs = []struct {
				plaintext []byte
				context1  []byte
				context2  []byte
			}{
				{
					plaintext: []byte("this data needs to be encrypted"),
					context1:  []byte("encryption context"),
					context2:  []byte("encryption context"),
				},
				{
					plaintext: []byte("this data needs to be encrypted"),
					context1:  []byte(""),
					context2:  []byte(""),
				},
				{
					plaintext: []byte("this data needs to be encrypted"),
					context1:  nil,
					context2:  nil,
				},
				{
					plaintext: []byte(""),
					context1:  nil,
					context2:  nil,
				},
				{
					plaintext: nil,
					context1:  []byte("encryption context"),
					context2:  []byte("encryption context"),
				},
				{
					plaintext: nil,
					context1:  []byte(""),
					context2:  []byte(""),
				},
				{
					plaintext: nil,
					context1:  nil,
					context2:  nil,
				},
				{
					plaintext: []byte("this data needs to be encrypted"),
					context1:  []byte(""),
					context2:  nil,
				},
				{
					plaintext: []byte("this data needs to be encrypted"),
					context1:  nil,
					context2:  []byte(""),
				},
			}
			for _, ti := range testInputs {
				ciphertext, err := enc.Encrypt(ti.plaintext, ti.context1)
				if err != nil {
					t.Fatalf("enc.Encrypt(ti.plaintext, ti.context1) err = %v, want nil", err)
				}
				decrypted, err := dec.Decrypt(ciphertext, ti.context2)
				if err != nil {
					t.Fatalf("dec.Decrypt(ciphertext, ti.context2) err = %v, want nil", err)
				}
				if !bytes.Equal(ti.plaintext, decrypted) {
					t.Errorf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, ti.plaintext)
				}
			}
		})
	}
}
