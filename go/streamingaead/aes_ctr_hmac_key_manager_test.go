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
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var aesCTRHMACKeySizes = []uint32{16, 32}

func TestAESCTRHMACGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	for _, keySize := range aesCTRHMACKeySizes {
		key := testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, keySize, commonpb.HashType_SHA256, keySize, commonpb.HashType_SHA256, 16, 4096)
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		p, err := keyManager.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if err := validateAESCTRHMACPrimitive(p, key); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESCTRHMACGetPrimitiveWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}

	testKeys := genInvalidAESCTRHMACKeys()
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

func TestAESCTRHMACNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	format := testutil.NewAESCTRHMACKeyFormat(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 16, 4096)
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

func TestAESCTRHMACNewKeyBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	for _, keySize := range aesCTRHMACKeySizes {
		format := testutil.NewAESCTRHMACKeyFormat(keySize, commonpb.HashType_SHA256, keySize, commonpb.HashType_SHA256, 16, 4096)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key := m.(*ctrhmacpb.AesCtrHmacStreamingKey)
		if err := validateAESCTRHMACKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESCTRHMACNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	// bad format
	badFormats := genInvalidAESCTRHMACKeyFormats()
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

func TestAESCTRHMACNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	for _, keySize := range aesCTRHMACKeySizes {
		format := testutil.NewAESCTRHMACKeyFormat(keySize, commonpb.HashType_SHA256, keySize, commonpb.HashType_SHA256, 16, 4096)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if keyData.TypeUrl != testutil.AESCTRHMACTypeURL {
			t.Errorf("incorrect type url")
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type")
		}
		key := new(ctrhmacpb.AesCtrHmacStreamingKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("incorrect key value")
		}
		if err := validateAESCTRHMACKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestAESCTRHMACNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	badFormats := genInvalidAESCTRHMACKeyFormats()
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

func TestAESCTRHMACDoesSupport(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	if !keyManager.DoesSupport(testutil.AESCTRHMACTypeURL) {
		t.Errorf("AESCTRHMACKeyManager must support %s", testutil.AESCTRHMACTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("AESCTRHMACKeyManager must support only %s", testutil.AESCTRHMACTypeURL)
	}
}

func TestAESCTRHMACTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	if keyManager.TypeURL() != testutil.AESCTRHMACTypeURL {
		t.Errorf("incorrect key type")
	}
}

func genInvalidAESCTRHMACKeys() []proto.Message {
	return []proto.Message{
		// not a AESCTRHMACKey
		testutil.NewAESCTRHMACKeyFormat(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 16, 4096),

		// bad key size
		testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 17, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),
		testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 17, commonpb.HashType_SHA256, 16, 4096),
		testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 33, commonpb.HashType_SHA256, 33, commonpb.HashType_SHA256, 16, 4096),

		// bad version
		testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion+1, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),
	}
}

func genInvalidAESCTRHMACKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESCTRHMACKeyFormat
		testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),

		// invalid key size
		testutil.NewAESCTRHMACKeyFormat(17, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),
		testutil.NewAESCTRHMACKeyFormat(16, commonpb.HashType_SHA256, 17, commonpb.HashType_SHA256, 16, 4096),
		testutil.NewAESCTRHMACKeyFormat(33, commonpb.HashType_SHA256, 33, commonpb.HashType_SHA256, 16, 4096),
	}
}

func validateAESCTRHMACKey(key *ctrhmacpb.AesCtrHmacStreamingKey, format *ctrhmacpb.AesCtrHmacStreamingKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("incorrect key size")
	}
	if key.Version != testutil.AESCTRHMACKeyVersion {
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
	p, err := subtle.NewAESCTRHMAC(
		key.KeyValue,
		key.Params.HkdfHashType.String(),
		int(key.Params.DerivedKeySize),
		key.Params.HmacParams.Hash.String(),
		int(key.Params.HmacParams.TagSize),
		int(key.Params.CiphertextSegmentSize),
		0,
	)
	if err != nil {
		return fmt.Errorf("invalid key")
	}
	return validateAESCTRHMACPrimitive(p, key)
}

func validateAESCTRHMACPrimitive(p interface{}, key *ctrhmacpb.AesCtrHmacStreamingKey) error {
	cipher := p.(*subtle.AESCTRHMAC)
	if !bytes.Equal(cipher.MainKey, key.KeyValue) {
		return fmt.Errorf("main key and primitive don't match")
	}
	return encryptDecrypt(cipher, cipher, 32, 32)
}
