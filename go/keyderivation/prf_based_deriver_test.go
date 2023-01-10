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

package keyderivation

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/signature"
	aesgcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestPRFBasedDeriver(t *testing.T) {
	prfs := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "SHA256",
			template: prf.HKDFSHA256PRFKeyTemplate(),
		},
	}
	// Derivation names match KEY_TEMPLATE_NAMES in
	// https://github.com/google/tink/blob/cd96c47ced3f72199832573cdccf18719dc7c73b/testing/cross_language/util/utilities.py.
	derivations := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128_GCM",
			template: aead.AES128GCMKeyTemplate(),
		},
		{
			name:     "AES256_GCM",
			template: aead.AES256GCMKeyTemplate(),
		},
		{
			name:     "AES256_GCM_RAW",
			template: aead.AES256GCMNoPrefixKeyTemplate(),
		},
		{
			name:     "XCHACHA20_POLY1305",
			template: aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			name:     "AES256_SIV",
			template: daead.AESSIVKeyTemplate(),
		},
		{
			name:     "HKDF_SHA256",
			template: prf.HKDFSHA256PRFKeyTemplate(),
		},
		{
			name:     "ED25519",
			template: signature.ED25519KeyTemplate(),
		},
	}
	salts := [][]byte{nil, []byte("salt")}
	for _, prf := range prfs {
		for _, der := range derivations {
			for _, salt := range salts {
				name := fmt.Sprintf("%s_%s", prf.name, der.name)
				if salt != nil {
					name += "_with_salt"
				}
				t.Run(name, func(t *testing.T) {
					prfKeyData, err := registry.NewKeyData(prf.template)
					if err != nil {
						t.Fatalf("registry.NewKeyData() err = %v, want nil", err)
					}
					d, err := newPRFBasedDeriver(prfKeyData, der.template)
					if err != nil {
						t.Fatalf("newPRFBasedDeriver() err = %v, want nil", err)
					}
					if _, err := d.DeriveKeyset(salt); err != nil {
						t.Errorf("DeriveKeyset() err = %v, want nil", err)
					}
					// We cannot test the derived keyset handle because, at this point, it
					// is filled with placeholder values for the key ID, status, and
					// output prefix type fields.
				})
			}
		}
	}
}

func TestPRFBasedDeriverWithHKDFRFCVectorForAESGCM(t *testing.T) {
	// This is the only HKDF vector that uses an accepted hash function and has
	// key size >= 32-bytes.
	// https://www.rfc-editor.org/rfc/rfc5869#appendix-A.2
	vec := struct {
		hash   commonpb.HashType
		key    string
		salt   string
		info   string
		outLen int
		okm    string
	}{
		hash:   commonpb.HashType_SHA256,
		key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		salt:   "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info:   "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		outLen: 82,
		okm:    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
	}
	prfKeyValue, err := hex.DecodeString(vec.key)
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	prfSalt, err := hex.DecodeString(vec.salt)
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	derivationSalt, err := hex.DecodeString(vec.info)
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	wantKeyValue, err := hex.DecodeString(vec.okm)
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}

	prfKey := &hkdfpb.HkdfPrfKey{
		Version: 0,
		Params: &hkdfpb.HkdfPrfParams{
			Hash: vec.hash,
			Salt: prfSalt,
		},
		KeyValue: prfKeyValue,
	}
	serializedPRFKey, err := proto.Marshal(prfKey)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	prfKeyData := &tinkpb.KeyData{
		TypeUrl:         prf.HKDFSHA256PRFKeyTemplate().GetTypeUrl(),
		Value:           serializedPRFKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}

	for _, test := range []struct {
		name               string
		derivedKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name:               "AES128_GCM",
			derivedKeyTemplate: aead.AES128GCMKeyTemplate(),
		},
		{
			name:               "AES256_GCM",
			derivedKeyTemplate: aead.AES256GCMKeyTemplate(),
		},
		{
			name:               "AES256_GCM_RAW",
			derivedKeyTemplate: aead.AES256GCMNoPrefixKeyTemplate(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Derive keyset.
			d, err := newPRFBasedDeriver(prfKeyData, test.derivedKeyTemplate)
			if err != nil {
				t.Fatalf("newPRFBasedDeriver() err = %v, want nil", err)
			}
			derivedHandle, err := d.DeriveKeyset(derivationSalt)
			if err != nil {
				t.Fatalf("DeriveKeyset() err = %v, want nil", err)
			}
			derivedKeyset := insecurecleartextkeyset.KeysetMaterial(derivedHandle)

			// Verify keyset.
			if len(derivedKeyset.GetKey()) != 1 {
				t.Fatalf("len(keyset) = %d, want 1", len(derivedKeyset.GetKey()))
			}
			key := derivedKeyset.GetKey()[0]
			if derivedKeyset.GetPrimaryKeyId() != key.GetKeyId() {
				t.Fatal("keyset has no primary key")
			}
			// Verify key attributes set by prfBasedDeriver.
			if got, want := key.GetStatus(), tinkpb.KeyStatusType_UNKNOWN_STATUS; got != want {
				t.Errorf("derived key status = %s, want %s", got, want)
			}
			if got, want := key.GetOutputPrefixType(), tinkpb.OutputPrefixType_UNKNOWN_PREFIX; got != want {
				t.Errorf("derived key output prefix type = %s, want %s", got, want)
			}
			// Verify key value.
			derivedKeyFormat := &aesgcmpb.AesGcmKeyFormat{}
			if err := proto.Unmarshal(test.derivedKeyTemplate.GetValue(), derivedKeyFormat); err != nil {
				t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
			}
			wantKeySize := int(derivedKeyFormat.GetKeySize())
			aesGCMKey := &aesgcmpb.AesGcmKey{}
			if err := proto.Unmarshal(key.GetKeyData().GetValue(), aesGCMKey); err != nil {
				t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
			}
			gotKeyValue := aesGCMKey.GetKeyValue()
			if len(gotKeyValue) != wantKeySize {
				t.Errorf("derived key value length = %d, want %d", len(gotKeyValue), wantKeySize)
			}
			if !bytes.Equal(gotKeyValue, wantKeyValue[:wantKeySize]) {
				t.Errorf("derived key value = %q, want %q", gotKeyValue, wantKeyValue[:wantKeySize])
			}
		})
	}
}

func TestNewPRFBasedDeriverRejectsInvalidInputs(t *testing.T) {
	validPRFKeyData, err := registry.NewKeyData(prf.HKDFSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("registry.NewKeyData() err = %v, want nil", err)
	}
	validDerivedKeyTemplate := aead.AES128GCMKeyTemplate()
	if _, err := newPRFBasedDeriver(validPRFKeyData, validDerivedKeyTemplate); err != nil {
		t.Fatalf("newPRFBasedDeriver() err = %v, want nil", err)
	}
	invalidPRFKeyData, err := registry.NewKeyData(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("registry.NewKeyData() err = %v, want nil", err)
	}
	// The derivation of KeysetDeriver keyset handles is not supported, i.e. a
	// KeysetDeriver key template cannot be used as the derivedKeyTemplate
	// argument in newPRFBasedDeriver().
	invalidDerivedKeyTemplate, err := CreatePRFBasedKeyTemplate(prf.HKDFSHA256PRFKeyTemplate(), aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("CreatePRFBasedKeyTemplate() err = %v, want nil", err)
	}
	for _, test := range []struct {
		name               string
		prfKeyData         *tinkpb.KeyData
		derivedKeyTemplate *tinkpb.KeyTemplate
	}{
		{
			name: "nil inputs",
		},
		{
			name:               "nil PRF key data",
			derivedKeyTemplate: validDerivedKeyTemplate,
		},
		{
			name:       "nil derived template",
			prfKeyData: validPRFKeyData,
		},
		{
			name:               "invalid PRF key data",
			prfKeyData:         invalidPRFKeyData,
			derivedKeyTemplate: validDerivedKeyTemplate,
		},
		{
			name:               "invalid derived template",
			prfKeyData:         validPRFKeyData,
			derivedKeyTemplate: invalidDerivedKeyTemplate,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newPRFBasedDeriver(test.prfKeyData, test.derivedKeyTemplate); err == nil {
				t.Errorf("newPRFBasedDeriver() err = nil, want non-nil")
			}
		})
	}
}
