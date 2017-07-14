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
  "github.com/google/tink/go/subtle/hmac"
  "github.com/google/tink/go/subtle/random"
  "github.com/google/tink/go/subtle/util"
  "github.com/golang/protobuf/proto"
  commonpb "github.com/google/tink/proto/common_go_proto"
  hmacpb "github.com/google/tink/proto/hmac_go_proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
  // Type url that this manager supports.
  HMAC_TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey"

  // Current version of this key manager.
  // Keys with version equal or smaller are supported.
  HMAC_KEY_VERSION = uint32(0)

  // Minimum key size in bytes.
  minKeySizeInBytes = uint32(16)

  // Minimum tag size in bytes. This provides minimum 80-bit security strength.
  minTagSizeInBytes = uint32(10)
)

// Maximum tag size in bytes for each hash type
var maxTagSizeInBytes = map[commonpb.HashType]uint32{
  commonpb.HashType_SHA1: uint32(20),
  commonpb.HashType_SHA256: uint32(32),
  commonpb.HashType_SHA512: uint32(64),
}

/**
 * This key manager generates new {@code HmacKey} keys and produces new instances
 * of {@code hmac}.
 */
type HmacKeyManager struct{}

// Assert that HmacKeyManager implements the KeyManager interface.
var _ tink.KeyManager = (*HmacKeyManager)(nil)

/**
 * @return a new HmacKeyManager.
 */
func NewHmacKeyManager() *HmacKeyManager {
  return new(HmacKeyManager)
}

/**
 * Constructs a HMAC instance for the key given in {@code serializedKey},
 * which must be a serialized key protocol buffer handled by this manager.
 */
func (keyManager *HmacKeyManager) GetPrimitiveFromSerializedKey(
    serializedKey []byte) (interface{}, error) {
  if len(serializedKey) == 0 {
    return nil, fmt.Errorf("hmac_key_manager: invalid serialized key")
  }
  key := new(hmacpb.HmacKey)
  if err := proto.Unmarshal(serializedKey, key); err != nil {
    return nil, fmt.Errorf("hmac_key_manager: invalid serialized key: %s", err)
  }
  return keyManager.GetPrimitiveFromKey(key)
}

/**
 * Constructs a HMAC instance for the key given in {@code m}.
 */
func (keyManager *HmacKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
  if m == nil {
    return nil, fmt.Errorf("hmac_key_manager: key cannot be nil")
  }
  key, ok := m.(*hmacpb.HmacKey)
  if !ok {
    return nil, fmt.Errorf("hmac_key_manager: expect HmacKey proto")
  }
  if err := keyManager.validateKey(key); err != nil {
    return nil, err
  }
  return &hmac.Hmac{
    HashFunc: util.GetHashFunc(key.Params.Hash),
    Key: key.KeyValue,
    TagSize: key.Params.TagSize,
  }, nil
}

/**
 * Generates a new key according to specification in {@code serializedKeyFormat},
 * which must be a serialized key format protocol buffer handled by this manager.
 *
 * @return the new generated key.
 */
func (keyManager *HmacKeyManager) NewKeyFromSerializedKeyFormat(
    serializedKeyFormat []byte) (proto.Message, error) {
  if len(serializedKeyFormat) == 0 {
    return nil, fmt.Errorf("hmac_key_manager: invalid serialized key format")
  }
  keyFormat := new(hmacpb.HmacKeyFormat)
  if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
    return nil, fmt.Errorf("hmac_key_manager: invalid serialized key format: %s", err)
  }
  return keyManager.NewKeyFromKeyFormat(keyFormat)
}

/**
 * Generates a new key according to specification in {@code m}.
 *
 * @return the new generated key.
 */
func (keyManager *HmacKeyManager) NewKeyFromKeyFormat(
    m proto.Message) (proto.Message, error) {
  if m == nil {
    return nil, fmt.Errorf("hmac_key_manager: key format cannot be nil")
  }
  keyFormat, ok := m.(*hmacpb.HmacKeyFormat)
  if !ok {
    return nil, fmt.Errorf("hmac_key_manager: expect HmacKeyFormat proto")
  }
  if err := keyManager.validateKeyFormat(keyFormat); err != nil {
    return nil, fmt.Errorf("hmac_key_manager: invalid key format (%s)", err)
  }
  keyValue := random.GetRandomBytes(keyFormat.KeySize)
  return &hmacpb.HmacKey{
    Version: HMAC_KEY_VERSION,
    Params: keyFormat.Params,
    KeyValue: keyValue,
  }, nil
}

/**
 * Generates a new {@code KeyData} according to specification in {@code serializedkeyFormat}.
 * This should be used solely by the key management API.
 *
 * @return the new generated key.
 */
func (keyManager *HmacKeyManager) NewKeyData(
    serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
  key, err := keyManager.NewKeyFromSerializedKeyFormat(serializedKeyFormat)
  if err != nil {
    return nil,
      fmt.Errorf("hmac_key_manager: unable to create new KeyData (%s)", err)
  }
  serializedKey, err := proto.Marshal(key)
  if err != nil {
    return nil,
      fmt.Errorf("hmac_key_manager: unable to create new KeyData (%s)", err)
  }
  return &tinkpb.KeyData{
    TypeUrl: HMAC_TYPE_URL,
    Value: serializedKey,
    KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
  }, nil
}

/**
 * @return true iff this KeyManager supports key type identified by {@code typeUrl}.
 */
func (_ *HmacKeyManager) DoesSupport(typeUrl string) bool {
  return typeUrl == HMAC_TYPE_URL
}

/**
 * @return the type URL that identifes the key type of keys managed by this KeyManager.
 */
func (_ *HmacKeyManager) GetKeyType() string {
  return HMAC_TYPE_URL
}

/**
 * Validates the HmacKey given in {@code key}.
 */
func (keyManager *HmacKeyManager) validateKey(key *hmacpb.HmacKey) error {
  err := util.ValidateVersion(key.Version, HMAC_KEY_VERSION)
  if err != nil {
    return fmt.Errorf("hmac_key_manager: %s", err)
  }
  keySize := uint32(len(key.KeyValue))
  if keySize < minKeySizeInBytes {
    return fmt.Errorf("hmac_key_manager: key too short")
  }
  return keyManager.validateKeyParams(key.Params)
}

/**
 * Validates the HmacKeyFormat given in {@code params}.
 */
func (keyManager *HmacKeyManager) validateKeyFormat(format *hmacpb.HmacKeyFormat) error {
  if format.KeySize < minKeySizeInBytes {
    return fmt.Errorf("hmac_key_manager: key too short")
  }
  return keyManager.validateKeyParams(format.Params)
}

/**
 * Validates the HmacParams given in {@code params}.
 */
func (_ *HmacKeyManager) validateKeyParams(params *hmacpb.HmacParams) error {
  maxTagSize, existed := maxTagSizeInBytes[params.Hash]
  if !existed {
    return fmt.Errorf("hmac_key_manager: unknown hash type")
  }
  if params.TagSize > maxTagSize {
    return fmt.Errorf("hmac_key_manager: tag size too big")
  }
  if params.TagSize < minTagSizeInBytes {
    return fmt.Errorf("hmac_key_manager: tag size too small")
  }
  return nil
}
