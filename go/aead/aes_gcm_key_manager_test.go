// Copyright 2018 Google LLC
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
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var keySizes = []uint32{16, 32}

func TestAESGCMGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	for _, keySize := range keySizes {
		key := testutil.NewAESGCMKey(testutil.AESGCMKeyVersion, keySize)
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("proto.Marshal() err = %q, want nil", err)
		}
		p, err := keyManager.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if err := validateAESGCMPrimitive(p, key); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESGCMGetPrimitiveWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	// invalid AESGCMKey
	testKeys := genInvalidAESGCMKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil
	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty array
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestAESGCMNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	format := testutil.NewAESGCMKeyFormat(32)
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Fatalf("keyManager.NewKey() err = %q, want nil", err)
		}
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keys[string(serializedKey)] = true

		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("keyManager.NewKeyData() err = %q, want nil", err)
		}
		serializedKey = keyData.Value
		keys[string(serializedKey)] = true
	}
	if len(keys) != nTest*2 {
		t.Errorf("key is repeated")
	}
}

func TestAESGCMNewKeyBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	for _, keySize := range keySizes {
		format := testutil.NewAESGCMKeyFormat(keySize)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key := m.(*gcmpb.AesGcmKey)
		if err := validateAESGCMKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESGCMNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	// bad format
	badFormats := genInvalidAESGCMKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil
	if _, err := keyManager.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty array
	if _, err := keyManager.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestAESGCMNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	for _, keySize := range keySizes {
		format := testutil.NewAESGCMKeyFormat(keySize)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if keyData.TypeUrl != testutil.AESGCMTypeURL {
			t.Errorf("incorrect type url")
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type")
		}
		key := new(gcmpb.AesGcmKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("incorrect key value")
		}
		if err := validateAESGCMKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESGCMNewKeyDataWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	badFormats := genInvalidAESGCMKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := keyManager.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := keyManager.NewKeyData([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestAESGCMDoesSupport(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	if !keyManager.DoesSupport(testutil.AESGCMTypeURL) {
		t.Errorf("AESGCMKeyManager must support %s", testutil.AESGCMTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("AESGCMKeyManager must support only %s", testutil.AESGCMTypeURL)
	}
}

func TestAESGCMTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM key manager: %s", err)
	}
	if keyManager.TypeURL() != testutil.AESGCMTypeURL {
		t.Errorf("incorrect key type")
	}
}

func TestAESGCMKeyMaterialType(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESGCMTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	if got, want := keyManager.KeyMaterialType(), tinkpb.KeyData_SYMMETRIC; got != want {
		t.Errorf("KeyMaterialType() = %v, want %v", got, want)
	}
}

func TestAESGCMDeriveKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESGCMTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}

	for _, test := range []struct {
		name    string
		keySize uint32
	}{
		{
			name:    "AES-128-GCM",
			keySize: 16,
		},
		{
			name:    "AES-256-GCM",
			keySize: 32,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyFormat := testutil.NewAESGCMKeyFormat(test.keySize)
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
			}

			rand := random.GetRandomBytes(test.keySize)
			buf := &bytes.Buffer{}
			buf.Write(rand) // never returns a non-nil error

			k, err := keyManager.DeriveKey(serializedKeyFormat, buf)
			if err != nil {
				t.Fatalf("keyManager.DeriveKey() err = %v, want nil", err)
			}
			key := k.(*gcmpb.AesGcmKey)
			if got, want := len(key.GetKeyValue()), int(test.keySize); got != want {
				t.Errorf("key length = %d, want %d", got, want)
			}
			if diff := cmp.Diff(key.GetKeyValue(), rand); diff != "" {
				t.Errorf("incorrect derived key: diff = %v", diff)
			}
		})
	}
}

func TestAESGCMDeriveKeyFailsWithInvalidKeyFormats(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESGCMTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}

	for _, test := range []struct {
		name      string
		keyFormat *gcmpb.AesGcmKeyFormat
		randLen   uint32
	}{
		{
			name:      "invalid key size",
			keyFormat: &gcmpb.AesGcmKeyFormat{KeySize: 50, Version: 0},
			randLen:   50,
		},
		{
			name:      "not enough randomness",
			keyFormat: &gcmpb.AesGcmKeyFormat{KeySize: 32, Version: 0},
			randLen:   10,
		},
		{
			name:      "invalid version",
			keyFormat: &gcmpb.AesGcmKeyFormat{KeySize: 32, Version: 100000},
			randLen:   32,
		},
		{
			name:      "empty key format",
			keyFormat: &gcmpb.AesGcmKeyFormat{},
			randLen:   16,
		},
		{
			name:    "nil key format",
			randLen: 16,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			serializedKeyFormat, err := proto.Marshal(test.keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", test.keyFormat, err)
			}
			buf := bytes.NewBuffer(random.GetRandomBytes(test.randLen))
			if _, err := keyManager.DeriveKey(serializedKeyFormat, buf); err == nil {
				t.Error("keyManager.DeriveKey() err = nil, want non-nil")
			}
		})
	}
}

func TestAESGCMDeriveKeyFailsWithMalformedSerializedKeyFormat(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESGCMTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	size := proto.Size(&gcmpb.AesGcmKeyFormat{KeySize: 16, Version: 0})
	malformedSerializedKeyFormat := random.GetRandomBytes(uint32(size))
	buf := bytes.NewBuffer(random.GetRandomBytes(32))
	if _, err := keyManager.DeriveKey(malformedSerializedKeyFormat, buf); err == nil {
		t.Error("keyManager.DeriveKey() err = nil, want non-nil")
	}
}

func TestAESGCMDeriveKeyFailsWithInsufficientRandomness(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESGCMTypeURL, err)
	}
	keyManager, ok := km.(internalregistry.DerivableKeyManager)
	if !ok {
		t.Fatalf("key manager is not DerivableKeyManager")
	}
	var keySize uint32 = 16
	keyFormat, err := proto.Marshal(testutil.NewAESGCMKeyFormat(keySize))
	if err != nil {
		t.Fatalf("proto.Marshal() err = %v, want nil", err)
	}
	{
		buf := bytes.NewBuffer(random.GetRandomBytes(keySize))
		if _, err := keyManager.DeriveKey(keyFormat, buf); err != nil {
			t.Errorf("keyManager.DeriveKey() err = %v, want nil", err)
		}
	}
	{
		insufficientBuf := bytes.NewBuffer(random.GetRandomBytes(keySize - 1))
		if _, err := keyManager.DeriveKey(keyFormat, insufficientBuf); err == nil {
			t.Errorf("keyManager.DeriveKey() err = nil, want non-nil")
		}
	}
}

func genInvalidAESGCMKeys() []proto.Message {
	return []proto.Message{
		// not a AESGCMKey
		testutil.NewAESGCMKeyFormat(32),
		// bad key size
		testutil.NewAESGCMKey(testutil.AESGCMKeyVersion, 17),
		testutil.NewAESGCMKey(testutil.AESGCMKeyVersion, 25),
		testutil.NewAESGCMKey(testutil.AESGCMKeyVersion, 33),
		// bad version
		testutil.NewAESGCMKey(testutil.AESGCMKeyVersion+1, 16),
	}
}

func genInvalidAESGCMKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESGCMKeyFormat
		testutil.NewAESGCMKey(testutil.AESGCMKeyVersion, 16),
		// invalid key size
		testutil.NewAESGCMKeyFormat(uint32(15)),
		testutil.NewAESGCMKeyFormat(uint32(23)),
		testutil.NewAESGCMKeyFormat(uint32(31)),
	}
}

func validateAESGCMKey(key *gcmpb.AesGcmKey, format *gcmpb.AesGcmKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("incorrect key size")
	}
	if key.Version != testutil.AESGCMKeyVersion {
		return fmt.Errorf("incorrect key version")
	}
	// try to encrypt and decrypt
	p, err := subtle.NewAESGCM(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key")
	}
	return validateAESGCMPrimitive(p, key)
}

func validateAESGCMPrimitive(p any, key *gcmpb.AesGcmKey) error {
	cipher := p.(*subtle.AESGCM)
	// try to encrypt and decrypt
	pt := random.GetRandomBytes(32)
	aad := random.GetRandomBytes(32)
	ct, err := cipher.Encrypt(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed")
	}
	decrypted, err := cipher.Decrypt(ct, aad)
	if err != nil {
		return fmt.Errorf("decryption failed")
	}
	if !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed")
	}
	return nil
}
