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
package mac_test

import (
  "testing"
  "reflect"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/mac/mac"
  "github.com/google/tink/go/subtle/hmac"
  "github.com/google/tink/go/subtle/util"
  "github.com/golang/protobuf/proto"
  hmacpb "github.com/google/tink/proto/hmac_go_proto"
  commonpb "github.com/google/tink/proto/common_go_proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var testKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func TestGetPrimitiveFromSerializedKeyBasic(t *testing.T) {
  var h mac.HmacKeyManager
  hmacKey := newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION, testKey)
  serializedKey, err := proto.Marshal(hmacKey)
  p, err := h.GetPrimitiveFromSerializedKey(serializedKey)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  checkPrimitive(p, hmacKey, t)
}

func TestGetPrimitiveFromInvalidSerializedKey(t *testing.T) {
  var h mac.HmacKeyManager
  // nil input
  if _, err := h.GetPrimitiveFromSerializedKey(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // void input
  if _, err := h.GetPrimitiveFromSerializedKey([]byte{}); err == nil {
    t.Errorf("expect an error when input is not a serialized HmacKey")
  }
  if _, err := h.GetPrimitiveFromSerializedKey([]byte{0}); err == nil {
    t.Errorf("expect an error when input is not a serialized HmacKey")
  }
  // input is serialization of another proto
  serializedKey, _ := proto.Marshal(newHmacParams(commonpb.HashType_SHA256, 32))
  if _, err := h.GetPrimitiveFromSerializedKey(serializedKey); err == nil {
    t.Errorf("expect an error when input is not a serialized HmacKey")
  }
}

func TestGetPrimitiveFromKeyBasic(t *testing.T) {
  var h mac.HmacKeyManager
  hmacKey := newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION, testKey)
  p, err := h.GetPrimitiveFromKey(hmacKey)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  checkPrimitive(p, hmacKey, t)
}

func TestGetPrimitiveFromInvalidKey(t *testing.T) {
  var h mac.HmacKeyManager
  var err error
  var key *hmacpb.HmacKey
  // nil input
  if _, err = h.GetPrimitiveFromKey(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // input is not a HmacKey
  hmacParams := newHmacParams(commonpb.HashType_SHA256, 32)
  if _, err = h.GetPrimitiveFromKey(hmacParams); err == nil {
    t.Errorf("expect an error when input is not a HmacKey")
  }
  // bad version
  key = newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION+1, testKey)
  if _, err = h.GetPrimitiveFromKey(key); err == nil {
    t.Errorf("expect an error when version is not valid")
  }
  // tag size too big
  key = newHmacKey(commonpb.HashType_SHA256, 33, mac.HMAC_KEY_VERSION, testKey)
  if _, err = h.GetPrimitiveFromKey(key); err == nil {
    t.Errorf("expect an error when tag size is too big")
  }
  // tag size too small
  key = newHmacKey(commonpb.HashType_SHA256, 1, mac.HMAC_KEY_VERSION, testKey)
  if _, err = h.GetPrimitiveFromKey(key); err == nil {
    t.Errorf("expect an error when tag size is too small")
  }
  // key too short
  key = newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION, []byte{1, 1})
  if _, err = h.GetPrimitiveFromKey(key); err == nil {
    t.Errorf("expect an error when key is too short")
  }
  // unknown hash type
  key = newHmacKey(commonpb.HashType_UNKNOWN_HASH, 32, mac.HMAC_KEY_VERSION, testKey)
  if _, err = h.GetPrimitiveFromKey(key); err == nil {
    t.Errorf("expect an error when hash type is unknown")
  }
}

func TestNewKeyMultipleTimes(t *testing.T) {
  var h mac.HmacKeyManager
  format := newHmacKeyFormat(commonpb.HashType_SHA256, 16, 32)
  serializedFormat, _ := proto.Marshal(format)
  keys := make(map[string]bool)
  nTest := 26
  for i := 0; i < nTest/2; i++ {
    key, _ := h.NewKeyFromSerializedKeyFormat(serializedFormat)
    serializedKey, _ := proto.Marshal(key)
    _, existed := keys[string(serializedKey)]
    if existed {
      t.Errorf("key is repeated after %d times", i*2+1)
    }
    keys[string(serializedKey)] = true

    key, _ = h.NewKeyFromKeyFormat(format)
    serializedKey, _ = proto.Marshal(key)
    _, existed = keys[string(serializedKey)]
    if existed {
      t.Errorf("key is repeated after %d times", i*2+2)
    }
    keys[string(serializedKey)] = true
  }
}

func TestNewKeyFromSerializedKeyFormatBasic(t *testing.T) {
  var h mac.HmacKeyManager
  format := newHmacKeyFormat(commonpb.HashType_SHA256, 32, 16)
  serializedFormat, err := proto.Marshal(format)
  m, err := h.NewKeyFromSerializedKeyFormat(serializedFormat)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  checkKeyFormat(format, m, t)
}

func TestNewKeyFromKeyFormatBasic(t *testing.T) {
  var h mac.HmacKeyManager
  format := newHmacKeyFormat(commonpb.HashType_SHA256, 32, 16)
  m, err := h.NewKeyFromKeyFormat(format)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  checkKeyFormat(format, m, t)
}

func TestNewKeyFromInvalidSerializedKeyFormat(t *testing.T) {
  var h mac.HmacKeyManager
  // nil input
  if _, err := h.NewKeyFromSerializedKeyFormat(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // void input
  if _, err := h.NewKeyFromSerializedKeyFormat([]byte{}); err == nil {
    t.Errorf("expect an error when input is not a serialized HmacKeyFormat")
  }
  if _, err := h.NewKeyFromSerializedKeyFormat([]byte{0}); err == nil {
    t.Errorf("expect an error when input is not a serialized HmacKeyFormat")
  }
  // input is serialization of another proto
  hmacKey := newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION, testKey)
  serializedFormat, _ := proto.Marshal(hmacKey)
  if _, err := h.NewKeyFromSerializedKeyFormat(serializedFormat); err == nil {
    t.Errorf("expect an error when input is not a serialized HmacKeyFormat")
  }
}

func TestNewKeyFromInvalidKeyFormat(t *testing.T) {
  var h mac.HmacKeyManager
  var err error
  var format *hmacpb.HmacKeyFormat
  // nil input
  if _, err := h.NewKeyFromKeyFormat(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // input is not a HmacKeyFormat
  hmacKey := newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION, testKey)
  if _, err = h.NewKeyFromKeyFormat(hmacKey); err == nil {
    t.Errorf("expect an error when input is not a HmacKeyFormat")
  }
  // key too short
  format = newHmacKeyFormat(commonpb.HashType_SHA256, 32, 1)
  if _, err := h.NewKeyFromKeyFormat(format); err == nil {
    t.Errorf("expect an error when key is too short")
  }
  // tag size too small
  format = newHmacKeyFormat(commonpb.HashType_SHA256, 1, 16)
  if _, err := h.NewKeyFromKeyFormat(format); err == nil {
    t.Errorf("expect an error when tag size is too small")
  }
  // tag size too big
  format = newHmacKeyFormat(commonpb.HashType_SHA256, 33, 16)
  if _, err := h.NewKeyFromKeyFormat(format); err == nil {
    t.Errorf("expect an error when tag size is too big")
  }
  // unknown hash type
  format = newHmacKeyFormat(commonpb.HashType_UNKNOWN_HASH, 32, 16)
  if _, err := h.NewKeyFromKeyFormat(format); err == nil {
    t.Errorf("expect an error when hash type is unknown")
  }
}

func TestNewKeyDataBasic(t *testing.T) {
  var h mac.HmacKeyManager
  format := newHmacKeyFormat(commonpb.HashType_SHA256, 32, 16)
  serializedFormat, _ := proto.Marshal(format)
  keyData, err := h.NewKeyData(serializedFormat)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  if keyData.TypeUrl != mac.HMAC_TYPE_URL {
    t.Errorf("incorrect type url")
  }
  if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
    t.Errorf("incorrect key material type")
  }
  var key hmacpb.HmacKey
  if err := proto.Unmarshal(keyData.Value, &key); err != nil {
    t.Errorf("incorrect key value")
  }
}

func TestInvalidNewKeyData(t *testing.T) {
  var h mac.HmacKeyManager
  // nil input
  if _, err := h.NewKeyData(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
  // input is not HmacKeyFormat
  key := newHmacKey(commonpb.HashType_SHA256, 32, mac.HMAC_KEY_VERSION, testKey)
  serializedKey, _ := proto.Marshal(key)
  if _, err := h.NewKeyData(serializedKey); err == nil {
    t.Errorf("expect an error when input is not serialized HmacKeyFormat")
  }
}

func TestDoesSupport(t *testing.T) {
  var h mac.HmacKeyManager
  if h.DoesSupport(mac.HMAC_TYPE_URL) == false {
    t.Errorf("HmacKeyManager must support %s", mac.HMAC_TYPE_URL)
  }
  badType := "some bad type"
  if h.DoesSupport(badType) {
    t.Errorf("HmacKeyManager must support only %s", mac.HMAC_TYPE_URL)
  }
}

func TestGetKeyType(t *testing.T) {
  var h mac.HmacKeyManager
  if h.GetKeyType() != mac.HMAC_TYPE_URL {
    t.Errorf("incorrect GetKeyType()")
  }
}

func TestKeyManagerInterface(t *testing.T) {
  // This line throws an error if Hmac doesn't implement KeyManager interface
  var _ tink.KeyManager = (*mac.HmacKeyManager)(nil)
}

func newHmacParams(hashType commonpb.HashType, tagSize uint32) *hmacpb.HmacParams {
  return &hmacpb.HmacParams{
    Hash: hashType,
    TagSize: tagSize,
  }
}

func newHmacKey(hashType commonpb.HashType, tagSize uint32,
                version uint32, keyValue []byte) *hmacpb.HmacKey {
  params := newHmacParams(hashType, tagSize)
  return &hmacpb.HmacKey{
    Version: version,
    Params: params,
    KeyValue: keyValue,
  }
}

func newHmacKeyFormat(hashType commonpb.HashType, tagSize uint32,
                      keySize uint32) *hmacpb.HmacKeyFormat {
  params := newHmacParams(hashType, tagSize)
  return &hmacpb.HmacKeyFormat{
    Params: params,
    KeySize: keySize,
  }
}

// Checks whether the given HmacKey matches the given key HmacKeyFormat
func checkKeyFormat(format *hmacpb.HmacKeyFormat, m proto.Message, t *testing.T) {
  key := m.(*hmacpb.HmacKey)
  if format.KeySize != uint32(len(key.KeyValue)) ||
      key.Params.TagSize != format.Params.TagSize ||
      key.Params.Hash != format.Params.Hash {
    t.Errorf("key format and generated key do not match")
  }
}

// Checks whether the given primitive matches the given HmacKey
func checkPrimitive(p interface{}, key *hmacpb.HmacKey, t *testing.T) {
  hm := p.(*hmac.Hmac)
  if !reflect.DeepEqual(hm.Key, key.KeyValue) ||
      hm.TagSize != key.Params.TagSize ||
      reflect.ValueOf(hm.HashFunc).Pointer() !=
        reflect.ValueOf(util.GetHashFunc(key.Params.Hash)).Pointer() {
    t.Errorf("primitive and key do not matched")
  }
  var m tink.Mac = hm
  if _, err := m.ComputeMac([]byte{1, 2, 3, 4, 5}); err != nil {
    t.Errorf("unable to use the generated primitive")
  }
}