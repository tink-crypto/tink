// Copyright 2020 Google LLC
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

package streamingaead_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/streamingaead/subtle"
	"github.com/google/tink/go/testutil"
	gcmhkdfpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var aesGCMHKDFKeySizes = []uint32{16, 32}

func TestAESGCMHKDFGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	for _, keySize := range aesGCMHKDFKeySizes {
		key := testutil.NewAESGCMHKDFKey(testutil.AESGCMHKDFKeyVersion, keySize, keySize, commonpb.HashType_SHA256, 4096)
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		p, err := keyManager.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if err := validatePrimitive(p, key); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESGCMHKDFGetPrimitiveWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}

	testKeys := genInvalidAESGCMHKDFKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}

	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestAESGCMHKDFNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	format := testutil.NewAESGCMHKDFKeyFormat(32, 32, commonpb.HashType_SHA256, 4096)
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Errorf("failed to marshal key: %s", err)
	}
	keys := make(map[string]struct{})
	n := 26
	for i := 0; i < n; i++ {
		key, _ := keyManager.NewKey(serializedFormat)
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		keys[string(serializedKey)] = struct{}{}

		keyData, _ := keyManager.NewKeyData(serializedFormat)
		serializedKey = keyData.Value
		keys[string(serializedKey)] = struct{}{}
	}
	if len(keys) != n*2 {
		t.Errorf("key is repeated")
	}
}

func TestAESGCMHKDFNewKeyBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	for _, keySize := range aesGCMHKDFKeySizes {
		format := testutil.NewAESGCMHKDFKeyFormat(
			keySize,
			keySize,
			commonpb.HashType_SHA256,
			4096,
		)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key := m.(*gcmhkdfpb.AesGcmHkdfStreamingKey)
		if err := validateAESGCMHKDFKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESGCMHKDFNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	// bad format
	badFormats := genInvalidAESGCMHKDFKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
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

func TestAESGCMHKDFNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	for _, keySize := range aesGCMHKDFKeySizes {
		format := testutil.NewAESGCMHKDFKeyFormat(
			keySize,
			keySize,
			commonpb.HashType_SHA256,
			4096,
		)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if keyData.TypeUrl != testutil.AESGCMHKDFTypeURL {
			t.Errorf("incorrect type url")
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type")
		}
		key := new(gcmhkdfpb.AesGcmHkdfStreamingKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("incorrect key value")
		}
		if err := validateAESGCMHKDFKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESGCMHKDFNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	badFormats := genInvalidAESGCMHKDFKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.NewKeyData([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestAESGCMHKDFDoesSupport(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	if !keyManager.DoesSupport(testutil.AESGCMHKDFTypeURL) {
		t.Errorf("AESGCMHKDFKeyManager must support %s", testutil.AESGCMHKDFTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("AESGCMHKDFKeyManager must support only %s", testutil.AESGCMHKDFTypeURL)
	}
}

func TestAESGCMHKDFTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	if keyManager.TypeURL() != testutil.AESGCMHKDFTypeURL {
		t.Errorf("incorrect key type")
	}
}

func genInvalidAESGCMHKDFKeys() []proto.Message {
	return []proto.Message{
		// not a AESGCMHKDFKey
		testutil.NewAESGCMHKDFKeyFormat(32, 32, commonpb.HashType_SHA256, 4096),
		// bad key size
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 17, 16, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 16, 17, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 33, 33, commonpb.HashType_SHA256, 4096),
		// bad version
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion+1, 16, 16, commonpb.HashType_SHA256, 4096),
	}
}

func genInvalidAESGCMHKDFKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESGCMKeyFormat
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 16, 16, commonpb.HashType_SHA256, 16),
		// invalid key size
		testutil.NewAESGCMHKDFKeyFormat(17, 16, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKeyFormat(16, 17, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKeyFormat(33, 33, commonpb.HashType_SHA256, 4096),
	}
}

func validateAESGCMHKDFKey(key *gcmhkdfpb.AesGcmHkdfStreamingKey, format *gcmhkdfpb.AesGcmHkdfStreamingKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("incorrect key size")
	}
	if key.Version != testutil.AESGCMKeyVersion {
		return fmt.Errorf("incorrect key version")
	}
	if key.Params.CiphertextSegmentSize != format.Params.CiphertextSegmentSize {
		return fmt.Errorf("incorrect ciphertext segment size")
	}
	if key.Params.DerivedKeySize != format.Params.DerivedKeySize {
		return fmt.Errorf("incorrect derived key size")
	}
	if key.Params.HkdfHashType != format.Params.HkdfHashType {
		return fmt.Errorf("incorrect HKDF hash type")
	}
	// try to encrypt and decrypt
	p, err := subtle.NewAESGCMHKDF(
		key.KeyValue,
		key.Params.HkdfHashType.String(),
		int(key.Params.DerivedKeySize),
		int(key.Params.CiphertextSegmentSize),
		0,
	)
	if err != nil {
		return fmt.Errorf("invalid key")
	}
	return validatePrimitive(p, key)
}

func validatePrimitive(p interface{}, key *gcmhkdfpb.AesGcmHkdfStreamingKey) error {
	cipher := p.(*subtle.AESGCMHKDF)
	if !bytes.Equal(cipher.MainKey, key.KeyValue) {
		return fmt.Errorf("main key and primitive don't match")
	}
	return encryptDecrypt(cipher, cipher, 32, 32)
}
