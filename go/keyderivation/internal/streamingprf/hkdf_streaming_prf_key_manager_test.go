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

package streamingprf_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyderivation/internal/streamingprf"
	"github.com/google/tink/go/subtle/random"
	aesgcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const hkdfStreamingPRFTypeURL = "type.googleapis.com/google.crypto.tink.HkdfStreamingPrfKey"

func TestHKDFStreamingPRFKeyManagerPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	for _, test := range []struct {
		name string
		hash commonpb.HashType
		salt []byte
	}{
		{
			name: "SHA256_nil_salt",
			hash: commonpb.HashType_SHA256,
		},
		{
			name: "SHA256_random_salt",
			hash: commonpb.HashType_SHA256,
			salt: random.GetRandomBytes(16),
		},
		{
			name: "SHA512_nil_salt",
			hash: commonpb.HashType_SHA512,
		},
		{
			name: "SHA512_random_salt",
			hash: commonpb.HashType_SHA512,
			salt: random.GetRandomBytes(16),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := &hkdfpb.HkdfPrfKey{
				Version: 0,
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					Salt: test.salt,
				},
				KeyValue: random.GetRandomBytes(32),
			}
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", key, err)
			}
			p, err := km.Primitive(serializedKey)
			if err != nil {
				t.Fatalf("Primitive() err = %v, want nil", err)
			}
			prf, ok := p.(streamingprf.StreamingPRF)
			if !ok {
				t.Fatal("primitive is not StreamingPRF")
			}
			r, err := prf.Compute(random.GetRandomBytes(32))
			if err != nil {
				t.Fatalf("Compute() err = %v, want nil", err)
			}
			limit := limitFromHash(t, test.hash)
			out := make([]byte, limit)
			n, err := r.Read(out)
			if n != limit || err != nil {
				t.Errorf("Read() not enough bytes: %d, %v", n, err)
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerPrimitiveRejectsIncorrectKeys(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	missingParamsKey := &hkdfpb.HkdfPrfKey{
		Version:  0,
		KeyValue: random.GetRandomBytes(32),
	}
	serializedMissingParamsKey, err := proto.Marshal(missingParamsKey)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", serializedMissingParamsKey, err)
	}
	aesGCMKey := &aesgcmpb.AesGcmKey{Version: 0}
	serializedAESGCMKey, err := proto.Marshal(aesGCMKey)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", aesGCMKey, err)
	}
	for _, test := range []struct {
		name          string
		serializedKey []byte
	}{
		{
			name: "nil key",
		},
		{
			name:          "zero-length key",
			serializedKey: []byte{},
		},
		{
			name:          "missing params",
			serializedKey: serializedMissingParamsKey,
		},
		{
			name:          "wrong key type",
			serializedKey: serializedAESGCMKey,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := km.Primitive(test.serializedKey); err == nil {
				t.Error("Primitive() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerPrimitiveRejectsInvalidKeys(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}

	validKey := &hkdfpb.HkdfPrfKey{
		Version: 0,
		Params: &hkdfpb.HkdfPrfParams{
			Hash: commonpb.HashType_SHA256,
			Salt: random.GetRandomBytes(16),
		},
		KeyValue: random.GetRandomBytes(32),
	}
	serializedValidKey, err := proto.Marshal(validKey)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", validKey, err)
	}
	if _, err := km.Primitive(serializedValidKey); err != nil {
		t.Errorf("Primitive() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name     string
		version  uint32
		hash     commonpb.HashType
		keyValue []byte
	}{
		{
			"invalid version",
			100,
			validKey.GetParams().GetHash(),
			validKey.GetKeyValue(),
		},
		{
			"invalid hash",
			validKey.GetVersion(),
			commonpb.HashType_SHA1,
			validKey.GetKeyValue(),
		},
		{
			"invalid key size",
			validKey.GetVersion(),
			validKey.GetParams().GetHash(),
			random.GetRandomBytes(12),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := &hkdfpb.HkdfPrfKey{
				Version: test.version,
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					// There is no concept of an invalid salt, as it can either be nil or
					// have a value.
					Salt: validKey.GetParams().GetSalt(),
				},
				KeyValue: test.keyValue,
			}
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", key, err)
			}
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Error("Primitive() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	for _, test := range []struct {
		name string
		hash commonpb.HashType
		salt []byte
	}{
		{
			name: "SHA256_nil_salt",
			hash: commonpb.HashType_SHA256,
		},
		{
			name: "SHA256_random_salt",
			hash: commonpb.HashType_SHA256,
			salt: random.GetRandomBytes(16),
		},
		{
			name: "SHA512_nil_salt",
			hash: commonpb.HashType_SHA512,
		},
		{
			name: "SHA512_random_salt",
			hash: commonpb.HashType_SHA512,
			salt: random.GetRandomBytes(16),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat := &hkdfpb.HkdfPrfKeyFormat{
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					Salt: test.salt,
				},
				KeySize: 32,
				Version: 0,
			}
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
			}
			k, err := km.NewKey(serializedKeyFormat)
			if err != nil {
				t.Errorf("NewKey() err = %v, want nil", err)
			}
			key, ok := k.(*hkdfpb.HkdfPrfKey)
			if !ok {
				t.Fatal("key is not HkdfPrfKey")
			}
			if key.GetVersion() != 0 {
				t.Errorf("GetVersion() = %d, want 0", key.GetVersion())
			}
			if got, want := key.GetParams().GetHash(), test.hash; got != want {
				t.Errorf("GetHash() = %v, want %v", got, want)
			}
			if got, want := key.GetParams().GetSalt(), test.salt; !bytes.Equal(got, want) {
				t.Errorf("GetSalt() = %v, want %v", got, want)
			}
			if len(key.GetKeyValue()) != int(keyFormat.GetKeySize()) {
				t.Errorf("len(key) = %d, want %d", len(key.GetKeyValue()), keyFormat.GetKeySize())
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerNewKeyRejectsIncorrectKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	missingParamsKeyFormat := &hkdfpb.HkdfPrfKeyFormat{
		Version: 0,
		KeySize: 32,
	}
	serializedMissingParamsKeyFormat, err := proto.Marshal(missingParamsKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", missingParamsKeyFormat, err)
	}
	aesGCMKeyFormat := &aesgcmpb.AesGcmKeyFormat{Version: 0}
	serializedAESGCMKeyFormat, err := proto.Marshal(aesGCMKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", aesGCMKeyFormat, err)
	}
	for _, test := range []struct {
		name                string
		serializedKeyFormat []byte
	}{
		{
			name: "nil key",
		},
		{
			name:                "zero-length key",
			serializedKeyFormat: []byte{},
		},
		{
			name:                "missing params",
			serializedKeyFormat: serializedMissingParamsKeyFormat,
		},
		{
			name:                "wrong key type",
			serializedKeyFormat: serializedAESGCMKeyFormat,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := km.NewKey(test.serializedKeyFormat); err == nil {
				t.Error("NewKey() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerNewKeyRejectsInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}

	validKeyFormat := &hkdfpb.HkdfPrfKeyFormat{
		Params: &hkdfpb.HkdfPrfParams{
			Hash: commonpb.HashType_SHA256,
			Salt: random.GetRandomBytes(16),
		},
		KeySize: 32,
	}
	serializedValidKeyFormat, err := proto.Marshal(validKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", validKeyFormat, err)
	}
	if _, err := km.NewKey(serializedValidKeyFormat); err != nil {
		t.Errorf("NewKey() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name    string
		hash    commonpb.HashType
		keySize uint32
	}{
		{
			"invalid hash",
			commonpb.HashType_SHA1,
			validKeyFormat.GetKeySize(),
		},
		{
			"invalid key size",
			validKeyFormat.GetParams().GetHash(),
			20,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat := &hkdfpb.HkdfPrfKeyFormat{
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					// There is no concept of an invalid salt, as it can either be nil or
					// have a value.
					Salt: validKeyFormat.GetParams().GetSalt(),
				},
				KeySize: test.keySize,
			}
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
			}
			if _, err := km.NewKey(serializedKeyFormat); err == nil {
				t.Error("NewKey() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	for _, test := range []struct {
		name string
		hash commonpb.HashType
		salt []byte
	}{
		{
			name: "SHA256_nil_salt",
			hash: commonpb.HashType_SHA256,
		},
		{
			name: "SHA256_random_salt",
			hash: commonpb.HashType_SHA256,
			salt: random.GetRandomBytes(16),
		},
		{
			name: "SHA512_nil_salt",
			hash: commonpb.HashType_SHA512,
		},
		{
			name: "SHA512_random_salt",
			hash: commonpb.HashType_SHA512,
			salt: random.GetRandomBytes(16),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat := &hkdfpb.HkdfPrfKeyFormat{
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					Salt: test.salt,
				},
				KeySize: 32,
				Version: 0,
			}
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
			}
			keyData, err := km.NewKeyData(serializedKeyFormat)
			if err != nil {
				t.Errorf("NewKeyData() err = %v, want nil", err)
			}
			if keyData.GetTypeUrl() != hkdfStreamingPRFTypeURL {
				t.Errorf("GetTypeUrl() = %s, want %s", keyData.GetTypeUrl(), hkdfStreamingPRFTypeURL)
			}
			if keyData.GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
				t.Errorf("GetKeyMaterialType() = %d, want %d", keyData.GetKeyMaterialType(), tinkpb.KeyData_SYMMETRIC)
			}
			key := &hkdfpb.HkdfPrfKey{}
			err = proto.Unmarshal(keyData.GetValue(), key)
			if err != nil {
				t.Fatalf("proto.Unmarshal() err = %v, want nil", err)
			}
			if key.GetVersion() != 0 {
				t.Errorf("GetVersion() = %d, want 0", key.GetVersion())
			}
			if got, want := key.GetParams().GetHash(), test.hash; got != want {
				t.Errorf("GetHash() = %v, want %v", got, want)
			}
			if got, want := key.GetParams().GetSalt(), test.salt; !bytes.Equal(got, want) {
				t.Errorf("GetSalt() = %v, want %v", got, want)
			}
			if len(key.GetKeyValue()) != int(keyFormat.GetKeySize()) {
				t.Errorf("len(key) = %d, want %d", len(key.GetKeyValue()), keyFormat.GetKeySize())
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerNewKeyDataRejectsIncorrectKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	missingParamsKeyFormat := &hkdfpb.HkdfPrfKeyFormat{
		Version: 0,
		KeySize: 32,
	}
	serializedMissingParamsKeyFormat, err := proto.Marshal(missingParamsKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", missingParamsKeyFormat, err)
	}
	aesGCMKeyFormat := &aesgcmpb.AesGcmKeyFormat{Version: 0}
	serializedAESGCMKeyFormat, err := proto.Marshal(aesGCMKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", aesGCMKeyFormat, err)
	}
	for _, test := range []struct {
		name                string
		serializedKeyFormat []byte
	}{
		{
			name: "nil key",
		},
		{
			name:                "zero-length key",
			serializedKeyFormat: []byte{},
		},
		{
			name:                "missing params",
			serializedKeyFormat: serializedMissingParamsKeyFormat,
		},
		{
			name:                "wrong key type",
			serializedKeyFormat: serializedAESGCMKeyFormat,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := km.NewKeyData(test.serializedKeyFormat); err == nil {
				t.Error("NewKeyData() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerNewKeyDataRejectsInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}

	validKeyFormat := &hkdfpb.HkdfPrfKeyFormat{
		Params: &hkdfpb.HkdfPrfParams{
			Hash: commonpb.HashType_SHA256,
			Salt: random.GetRandomBytes(16),
		},
		KeySize: 32,
	}
	serializedValidKeyFormat, err := proto.Marshal(validKeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", validKeyFormat, err)
	}
	if _, err := km.NewKeyData(serializedValidKeyFormat); err != nil {
		t.Errorf("NewKeyData() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name    string
		hash    commonpb.HashType
		keySize uint32
	}{
		{
			"invalid hash",
			commonpb.HashType_SHA1,
			validKeyFormat.GetKeySize(),
		},
		{
			"invalid key size",
			validKeyFormat.GetParams().GetHash(),
			20,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat := &hkdfpb.HkdfPrfKeyFormat{
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					// There is no concept of an invalid salt, as it can either be nil or
					// have a value.
					Salt: validKeyFormat.GetParams().GetSalt(),
				},
				KeySize: test.keySize,
			}
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
			}
			if _, err := km.NewKeyData(serializedKeyFormat); err == nil {
				t.Error("NewKeyData() err = nil, want non-nil")
			}
		})
	}
}

func TestHKDFStreamingPRFKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	if !km.DoesSupport(hkdfStreamingPRFTypeURL) {
		t.Errorf("DoesSupport(%q) = false, want true", hkdfStreamingPRFTypeURL)
	}
	if unsupported := "unsupported.key.type"; km.DoesSupport(unsupported) {
		t.Errorf("DoesSupport(%q) = true, want false", unsupported)
	}
}

func TestHKDFStreamingPRFKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	if km.TypeURL() != hkdfStreamingPRFTypeURL {
		t.Errorf("TypeURL() = %q, want %q", km.TypeURL(), hkdfStreamingPRFTypeURL)
	}
}
