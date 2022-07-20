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
//
////////////////////////////////////////////////////////////////////////////////

package aead_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
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
		key := testutil.NewAESGCMKey(testutil.AESGCMKeyVersion, uint32(keySize))
		serializedKey, _ := proto.Marshal(key)
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
		serializedKey, _ := proto.Marshal(testKeys[i])
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
	serializedFormat, _ := proto.Marshal(format)
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, _ := keyManager.NewKey(serializedFormat)
		serializedKey, _ := proto.Marshal(key)
		keys[string(serializedKey)] = true

		keyData, _ := keyManager.NewKeyData(serializedFormat)
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
		format := testutil.NewAESGCMKeyFormat(uint32(keySize))
		serializedFormat, _ := proto.Marshal(format)
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
		serializedFormat, _ := proto.Marshal(badFormats[i])
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
		format := testutil.NewAESGCMKeyFormat(uint32(keySize))
		serializedFormat, _ := proto.Marshal(format)
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
		serializedFormat, _ := proto.Marshal(badFormats[i])
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

func validateAESGCMPrimitive(p interface{}, key *gcmpb.AesGcmKey) error {
	cipher := p.(*subtle.AESGCM)
	if !bytes.Equal(cipher.Key(), key.KeyValue) {
		return fmt.Errorf("key and primitive don't match")
	}
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
