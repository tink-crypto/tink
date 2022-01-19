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
	gcmsivpb "github.com/google/tink/go/proto/aes_gcm_siv_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var aesGCMSIVKeySizes = []uint32{16, 32}

func TestAESGCMSIVGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	for _, keySize := range aesGCMSIVKeySizes {
		key := testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, uint32(keySize))
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key for keySize=%d, skipping test iteration; err=%v", key, keySize, err)
			continue
		}
		p, err := keyManager.Primitive(serializedKey)
		if err != nil {
			t.Errorf("Primitive(serializedKey=%v): Unexpected error creating AES-GCM-SIV primitive with keySize=%d, skipping test iteration; err=%v", serializedKey, keySize, err)
			continue
		}
		if err := validateAESGCMSIVPrimitive(p, key); err != nil {
			t.Errorf("validateAESGCMSIVPrimitive(key=%v): Error validating AES-GCM-SIV primitive with keySize=%d, skipping test iteration; err=%v", key, keySize, err)
			continue
		}
	}
}

func TestAESGCMSIVGetPrimitiveWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	// invalid AESGCMSIVKey
	testKeys := genInvalidAESGCMSIVKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("Primitive(serializedKey=%v): Key %d, got err = nil, want err != nil.", serializedKey, i)
		}
	}
	// nil
	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("Primitive(serializedKey=nil): Key nil, got err = nil, want err != nil.")
	}
	// empty array
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("Primitive(serializedKey=[]): Key empty, got err = nil, want err != nil.")
	}
}

func TestAESGCMSIVNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	format := testutil.NewAESGCMSIVKeyFormat(32)
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(data=%+v): Failed to serialize key format; err=%v", format, err)
	}
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("NewKey(serializedKeyFormat=%v): Failed to create new key on iteration %d; err=%v", serializedFormat, i, err)
		}
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key on iteration %d; err=%v", key, i, err)
		}
		keys[string(serializedKey)] = true

		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("NewKeyData(serializedFormat=%v): Failed to create new key data on iteration %d; err=%v", serializedFormat, i, err)
		}
		serializedKey = keyData.Value
		keys[string(serializedKey)] = true
	}
	if len(keys) != nTest*2 {
		t.Errorf("TestAESGCMSIVNewKeyMultipleTimes(): Got %d unique keys, want %d.", len(keys), nTest*2)
	}
}

func TestAESGCMSIVNewKeyBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	for _, keySize := range aesGCMSIVKeySizes {
		format := testutil.NewAESGCMSIVKeyFormat(uint32(keySize))
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key format for keySize=%d, skipping remainder of test iteration; err=%v", format, keySize, err)
			continue
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("NewKey(serializedKeyFormat=%v): Unexpected error for keySize=%d, skipping remainder of test iteration; err=%v", serializedFormat, keySize, err)
			continue
		}
		key := m.(*gcmsivpb.AesGcmSivKey)
		if err := validateAESGCMSIVKey(key, format); err != nil {
			t.Errorf("validateAESGCMSIVKey(key=%v): Error trying to validate key for keySize=%d; err=%v", key, keySize, err)
		}
	}
}

func TestAESGCMSIVNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	// bad format
	badFormats := genInvalidAESGCMSIVKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, _ := proto.Marshal(badFormats[i])
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Errorf("NewKey(serializedKeyFormat=%v): Key %d, got err = nil, want err != nil", serializedFormat, i)
		}
	}
	// nil
	if _, err := keyManager.NewKey(nil); err == nil {
		t.Errorf("NewKey(serializedKeyFormat=nil): Key nil, got err = nil, want err != nil")
	}
	// empty array
	if _, err := keyManager.NewKey([]byte{}); err == nil {
		t.Errorf("NewKey(serializedKeyFormat=[]): Key empty, got err = nil, want err != nil")
	}
}

func TestAESGCMSIVNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	for _, keySize := range aesGCMSIVKeySizes {
		format := testutil.NewAESGCMSIVKeyFormat(uint32(keySize))
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key format for keySize=%d, skipping remainder of test iteration; err=%v", format, keySize, err)
			continue
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Failed to create keyData for keySize=%d, skipping remainder of test iteration; err=%v", serializedFormat, keySize, err)
			continue
		}
		if keyData.TypeUrl != testutil.AESGCMSIVTypeURL {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Incorrect type url for keySize=%d, got %s, want %s.", serializedFormat, keySize, keyData.TypeUrl, testutil.AESGCMSIVTypeURL)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Incorrect key material type for keySize=%d, got %d, want %d.", serializedFormat, keySize, keyData.KeyMaterialType, tinkpb.KeyData_SYMMETRIC)
		}
		key := new(gcmsivpb.AesGcmSivKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("proto.Unmarshal(data=%v): Failed to load keyData into key for keySize=%d, skipping remainder of test iteration; err=%v", keyData.Value, keySize, err)
			continue
		}
		if err := validateAESGCMSIVKey(key, format); err != nil {
			t.Errorf("validateAESGCMSIVKey(key=%v): Failed to validate key for keySize=%d; err=%v", key, keySize, err)
		}
	}
}

func TestAESGCMSIVNewKeyDataWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	badFormats := genInvalidAESGCMSIVKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Key %d, failed to serialize key format, skipping remainder of test iteration; err=%v", badFormats[i], i, err)
			continue
		}
		if _, err := keyManager.NewKeyData(serializedFormat); err == nil {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Key %d, got err = nil, want err != nil.", serializedFormat, i)
		}
	}
	// nil input
	if _, err := keyManager.NewKeyData(nil); err == nil {
		t.Errorf("NewKeyData(serializedKeyFormat=nil): Key nil, got err = nil, want err != nil")
	}
	// empty input
	if _, err := keyManager.NewKeyData([]byte{}); err == nil {
		t.Errorf("NewKeyData(serializedKeyFormat=[]): Key empty, got err = nil, want err != nil")
	}
}

func TestAESGCMSIVDoesSupport(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	if !keyManager.DoesSupport(testutil.AESGCMSIVTypeURL) {
		t.Errorf("DoesSupport(typeURL=%s): got false, want true", testutil.AESGCMSIVTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("DoesSupport(typeURL=\"some bad type\"): got true, want false")
	}
}

func TestAESGCMSIVTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	if keyManager.TypeURL() != testutil.AESGCMSIVTypeURL {
		t.Errorf("GetKeyManager(%s): Incorrect key type for key manager, got %s, want %s.", testutil.AESGCMSIVTypeURL, keyManager.TypeURL(), testutil.AESGCMSIVTypeURL)
	}
}

func genInvalidAESGCMSIVKeys() []proto.Message {
	return []proto.Message{
		// not a AESGCMSIVKey
		testutil.NewAESGCMSIVKeyFormat(32),
		// bad key size
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 17),
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 25),
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 33),
		// bad version
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion+1, 16),
	}
}

func genInvalidAESGCMSIVKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESGCMSIVKeyFormat
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 16),
		// invalid key size
		testutil.NewAESGCMSIVKeyFormat(uint32(15)),
		testutil.NewAESGCMSIVKeyFormat(uint32(23)),
		testutil.NewAESGCMSIVKeyFormat(uint32(31)),
	}
}

func validateAESGCMSIVKey(key *gcmsivpb.AesGcmSivKey, format *gcmsivpb.AesGcmSivKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("Incorrect key size, got %d, want %d", uint32(len(key.KeyValue)), format.KeySize)
	}
	if key.Version != testutil.AESGCMSIVKeyVersion {
		return fmt.Errorf("Incorrect key version, got %d, want %d", key.Version, testutil.AESGCMSIVKeyVersion)
	}
	// Try to encrypt and decrypt random data.
	p, err := subtle.NewAESGCMSIV(key.KeyValue)
	if err != nil {
		return fmt.Errorf("subtle.NewAESGCMSIV(key=%v): Invalid key; err=%v", key.KeyValue, err)
	}
	return validateAESGCMSIVPrimitive(p, key)
}

func validateAESGCMSIVPrimitive(p interface{}, key *gcmsivpb.AesGcmSivKey) error {
	cipher := p.(*subtle.AESGCMSIV)
	if !bytes.Equal(cipher.Key, key.KeyValue) {
		return fmt.Errorf("Inputted key and primitive key don't match; input=%v, primitive=%v", key.KeyValue, cipher.Key)
	}
	// Try to encrypt and decrypt random data.
	pt := random.GetRandomBytes(32)
	aad := random.GetRandomBytes(32)
	ct, err := cipher.Encrypt(pt, aad)
	if err != nil {
		return fmt.Errorf("subtle.AESGCMSIV.Encrypt(pt=%v, aad=%v): Encryption failed; err=%v", pt, aad, err)
	}
	decrypted, err := cipher.Decrypt(ct, aad)
	if err != nil {
		return fmt.Errorf("subtle.AESGCMSIV.Decrypt(ct=%v, aad=%v): Decryption failed; err=%v", ct, aad, err)
	}
	if !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("subtle.AESGCMSIV.Decrypt(ct=%v, aad=%v): Decrypted bytes did not match original, got %v, want %v", ct, aad, decrypted, pt)
	}
	return nil
}
