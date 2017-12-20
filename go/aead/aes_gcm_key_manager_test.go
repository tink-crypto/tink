// Copyright 2017 Google Inc.
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
  "github.com/google/tink/go/util/util"
  "github.com/google/tink/go/util/testutil"
  "github.com/google/tink/go/aead/aead"
  "github.com/google/tink/go/subtle/aes"
  "github.com/google/tink/go/subtle/random"
  "github.com/golang/protobuf/proto"
  gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var keySizes = []uint32{16, 24, 32}

func TestNewAesGcmKeyManager(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  if keyManager == nil {
    t.Errorf("NewAesGcmKeyManager() returns nil")
  }
}

func TestAesGcmGetPrimitiveBasic(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  for _, keySize := range keySizes {
    key := testutil.NewAesGcmKey(uint32(keySize))
    p, err := keyManager.GetPrimitiveFromKey(key)
    if err != nil {
      t.Errorf("unexpected error: %s", err)
    }
    if err := validateAesGcmPrimitive(p, key); err != nil {
      t.Errorf("%s", err)
    }

    serializedKey, _ := proto.Marshal(key)
    p, err = keyManager.GetPrimitiveFromSerializedKey(serializedKey)
    if err != nil {
      t.Errorf("unexpected error: %s", err)
    }
    if err := validateAesGcmPrimitive(p, key); err != nil {
      t.Errorf("%s", err)
    }
  }
}

func TestAesGcmGetPrimitiveWithInvalidInput(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  // invalid AesGcmKey
  testKeys := genInvalidAesGcmKeys()
  for i := 0; i < len(testKeys); i++ {
    if _, err := keyManager.GetPrimitiveFromKey(testKeys[i]); err == nil {
      t.Errorf("expect an error in test case %d", i)
    }
    serializedKey, _ := proto.Marshal(testKeys[i])
    if _, err := keyManager.GetPrimitiveFromSerializedKey(serializedKey); err == nil {
      t.Errorf("expect an error in test case %d", i)
    }
  }
  // nil
  if _, err := keyManager.GetPrimitiveFromKey(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  if _, err := keyManager.GetPrimitiveFromSerializedKey(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // empty array
  if _, err := keyManager.GetPrimitiveFromSerializedKey([]byte{}); err == nil {
    t.Errorf("expect an error when input is empty")
  }
}

func TestAesGcmNewKeyMultipleTimes(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  format := util.NewAesGcmKeyFormat(32)
  serializedFormat, _ := proto.Marshal(format)
  keys := make(map[string]bool)
  nTest := 26
  for i := 0; i < nTest; i++ {
    key, _ := keyManager.NewKeyFromSerializedKeyFormat(serializedFormat)
    serializedKey, _ := proto.Marshal(key)
    keys[string(serializedKey)] = true

    key, _ = keyManager.NewKeyFromKeyFormat(format)
    serializedKey, _ = proto.Marshal(key)
    keys[string(serializedKey)] = true
  }
  if len(keys) != nTest*2 {
    t.Errorf("key is repeated")
  }
}

func TestAesGcmNewKeyBasic(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  for _, keySize := range keySizes {
    format := util.NewAesGcmKeyFormat(uint32(keySize))
    m, err := keyManager.NewKeyFromKeyFormat(format)
    if err != nil {
      t.Errorf("unexpected error: %s", err)
    }
    key := m.(*gcmpb.AesGcmKey)
    if err := validateAesGcmKey(key, format); err != nil {
      t.Errorf("%s", err)
    }

    serializedFormat, _ := proto.Marshal(format)
    m, err = keyManager.NewKeyFromSerializedKeyFormat(serializedFormat)
    if err != nil {
      t.Errorf("unexpected error: %s", err)
    }
    key = m.(*gcmpb.AesGcmKey)
    if err := validateAesGcmKey(key, format); err != nil {
      t.Errorf("%s", err)
    }
  }
}

func TestAesGcmNewKeyWithInvalidInput(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  // bad format
  badFormats := genInvalidAesGcmKeyFormats()
  for i := 0; i < len(badFormats); i++ {
    if _, err := keyManager.NewKeyFromKeyFormat(badFormats[i]); err == nil {
      t.Errorf("expect an error in test case %d", i)
    }
    serializedFormat, _ := proto.Marshal(badFormats[i])
    if _, err := keyManager.NewKeyFromSerializedKeyFormat(serializedFormat); err == nil {
      t.Errorf("expect an error in test case %d", i)
    }
  }
  // nil
  if _, err := keyManager.NewKeyFromKeyFormat(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  if _, err := keyManager.NewKeyFromSerializedKeyFormat(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // empty array
  if _, err := keyManager.NewKeyFromSerializedKeyFormat([]byte{}); err == nil {
    t.Errorf("expect an error when input is empty")
  }
}

func TestAesGcmNewKeyDataBasic(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  for _, keySize := range keySizes {
    format := util.NewAesGcmKeyFormat(uint32(keySize))
    serializedFormat, _ := proto.Marshal(format)
    keyData, err := keyManager.NewKeyData(serializedFormat)
    if err != nil {
      t.Errorf("unexpected error: %s", err)
    }
    if keyData.TypeUrl != aead.AES_GCM_TYPE_URL {
      t.Errorf("incorrect type url")
    }
    if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
      t.Errorf("incorrect key material type")
    }
    key := new(gcmpb.AesGcmKey)
    if err := proto.Unmarshal(keyData.Value, key); err != nil {
      t.Errorf("incorrect key value")
    }
    if err := validateAesGcmKey(key, format); err != nil {
      t.Errorf("%s", err)
    }
  }
}

func TestAesGcmNewKeyDataWithInvalidInput(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  badFormats := genInvalidAesGcmKeyFormats()
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

func TestAesGcmDoesSupport(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  if !keyManager.DoesSupport(aead.AES_GCM_TYPE_URL) {
    t.Errorf("AesGcmKeyManager must support %s", aead.AES_GCM_TYPE_URL)
  }
  if keyManager.DoesSupport("some bad type") {
    t.Errorf("AesGcmKeyManager must support only %s", aead.AES_GCM_TYPE_URL)
  }
}

func TestAesGcmGetKeyType(t *testing.T) {
  keyManager := aead.NewAesGcmKeyManager()
  if keyManager.GetKeyType() != aead.AES_GCM_TYPE_URL {
    t.Errorf("incorrect key type")
  }
}

func genInvalidAesGcmKeys() []proto.Message {
  return []proto.Message{
    // not a AesGcmKey
    util.NewAesGcmKeyFormat(32),
    // bad key size
    util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION, random.GetRandomBytes(17)),
    util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION, random.GetRandomBytes(25)),
    util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION, random.GetRandomBytes(33)),
    // bad version
    util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION+1, random.GetRandomBytes(16)),
  }
}

func genInvalidAesGcmKeyFormats() []proto.Message {
  return []proto.Message{
    // not AesGcmKeyFormat
    util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION, random.GetRandomBytes(16)),
    // invalid key size
    util.NewAesGcmKeyFormat(uint32(15)),
    util.NewAesGcmKeyFormat(uint32(23)),
    util.NewAesGcmKeyFormat(uint32(31)),
  }
}

func validateAesGcmKey(key *gcmpb.AesGcmKey, format *gcmpb.AesGcmKeyFormat) error {
  if uint32(len(key.KeyValue)) != format.KeySize {
    return fmt.Errorf("incorrect key size")
  }
  if key.Version != aead.AES_GCM_KEY_VERSION {
    return fmt.Errorf("incorrect key version")
  }
  // try to encrypt and decrypt
  p, err := aes.NewAesGcm(key.KeyValue)
  if err != nil {
    return fmt.Errorf("invalid key")
  }
  return validateAesGcmPrimitive(p, key)
}

func validateAesGcmPrimitive(p interface{}, key *gcmpb.AesGcmKey) error {
  cipher := p.(*aes.AesGcm)
  if !bytes.Equal(cipher.Key, key.KeyValue) {
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