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
package mac

import (
  "fmt"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/util/util"
  "github.com/google/tink/go/subtle/hmac"
  "github.com/google/tink/go/subtle/random"
  "github.com/golang/protobuf/proto"
  hmacpb "github.com/google/tink/proto/hmac_go_proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
  // Type url that this manager supports.
  HMAC_TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey"

  // Current version of this key manager.
  // Keys with version equal or smaller are supported.
  HMAC_KEY_VERSION = uint32(0)
)

var errInvalidHmacKey = fmt.Errorf("hmac_key_manager: invalid key")
var errInvalidHmacKeyFormat = fmt.Errorf("hmac_key_manager: invalid key format")

// HmacKeyManager generates new HmacKeys and produces new instances of Hmac.
type HmacKeyManager struct{}

// Assert that HmacKeyManager implements the KeyManager interface.
var _ tink.KeyManager = (*HmacKeyManager)(nil)

// NewHmacKeyManager returns a new HmacKeyManager.
func NewHmacKeyManager() *HmacKeyManager {
  return new(HmacKeyManager)
}

// GetPrimitiveFromSerializedKey constructs a Hmac instance for the given
// serialized HmacKey.
func (km *HmacKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
  if len(serializedKey) == 0 {
    return nil, errInvalidHmacKey
  }
  key := new(hmacpb.HmacKey)
  if err := proto.Unmarshal(serializedKey, key); err != nil {
    return nil, errInvalidHmacKey
  }
  return km.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKey constructs a HMAC instance for the given HmacKey.
func (km *HmacKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
  key, ok := m.(*hmacpb.HmacKey)
  if !ok {
    return nil, errInvalidHmacKey
  }
  if err := km.validateKey(key); err != nil {
    return nil, err
  }
  hash := util.GetHashName(key.Params.Hash)
  hmac, err := hmac.New(hash, key.KeyValue, key.Params.TagSize)
  if err != nil {
    return nil, err
  }
  return hmac, nil
}

// NewKeyFromSerializedKeyFormat generates a new HmacKey according to specification
// in the given serialized HmacKeyFormat.
func (km *HmacKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
  if len(serializedKeyFormat) == 0 {
    return nil, errInvalidHmacKeyFormat
  }
  keyFormat := new(hmacpb.HmacKeyFormat)
  if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
    return nil, errInvalidHmacKeyFormat
  }
  return km.NewKeyFromKeyFormat(keyFormat)
}

// NewKeyFromKeyFormat generates a new HmacKey according to specification in
// the given HmacKeyFormat.
func (km *HmacKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
  keyFormat, ok := m.(*hmacpb.HmacKeyFormat)
  if !ok {
    return nil, errInvalidHmacKeyFormat
  }
  if err := km.validateKeyFormat(keyFormat); err != nil {
    return nil, fmt.Errorf("hmac_key_manager: invalid key format: %s", err)
  }
  keyValue := random.GetRandomBytes(keyFormat.KeySize)
  return util.NewHmacKey(keyFormat.Params, HMAC_KEY_VERSION, keyValue), nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HmacKeyFormat. This should be used solely by the key management API.
func (km *HmacKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
  key, err := km.NewKeyFromSerializedKeyFormat(serializedKeyFormat)
  if err != nil {
    return nil, err
  }
  serializedKey, err := proto.Marshal(key)
  if err != nil {
    return nil, errInvalidHmacKeyFormat
  }
  return util.NewKeyData(HMAC_TYPE_URL, serializedKey, tinkpb.KeyData_SYMMETRIC), nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (_ *HmacKeyManager) DoesSupport(typeUrl string) bool {
  return typeUrl == HMAC_TYPE_URL
}

// GetKeyType returns the type URL of keys managed by this KeyManager.
func (_ *HmacKeyManager) GetKeyType() string {
  return HMAC_TYPE_URL
}

// validateKey validates the given HmacKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (_ *HmacKeyManager) validateKey(key *hmacpb.HmacKey) error {
  err := util.ValidateVersion(key.Version, HMAC_KEY_VERSION)
  if err != nil {
    return fmt.Errorf("hmac_key_manager: %s", err)
  }
  keySize := uint32(len(key.KeyValue))
  hash := util.GetHashName(key.Params.Hash)
  return hmac.ValidateParams(hash, keySize, key.Params.TagSize)
}

// validateKeyFormat validates the given HmacKeyFormat
func (_ *HmacKeyManager) validateKeyFormat(format *hmacpb.HmacKeyFormat) error {
  hash := util.GetHashName(format.Params.Hash)
  return hmac.ValidateParams(hash, format.KeySize, format.Params.TagSize)
}