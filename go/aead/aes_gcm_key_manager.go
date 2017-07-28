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
package aead

import (
  "fmt"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/util/util"
  "github.com/google/tink/go/subtle/aes"
  "github.com/google/tink/go/subtle/random"
  "github.com/golang/protobuf/proto"
  gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
  // Supported version
  AES_GCM_KEY_VERSION = 0

  // Supported type url
  AES_GCM_TYPE_URL = "type.googleapis.com/google.crypto.tink.AesGcmKey"
)

// common errors
var errInvalidAesGcmKey = fmt.Errorf("aes_gcm_key_manager: invalid key")
var errInvalidAesGcmKeyFormat = fmt.Errorf("aes_gcm_key_manager: invalid key format")

// AesGcmKeyManager is an implementation of KeyManager interface.
// It generates new AesGcmKey keys and produces new instances of AesGcm subtle.
type AesGcmKeyManager struct {}

// Assert that aesGcmKeyManager implements the KeyManager interface.
var _ tink.KeyManager = (*AesGcmKeyManager)(nil)

// NewAesGcmKeyManager creates a new aesGcmKeyManager.
func NewAesGcmKeyManager() *AesGcmKeyManager {
  return new(AesGcmKeyManager)
}

// GetPrimitiveFromSerializedKey creates an AesGcm subtle for the given
// serialized AesGcmKey proto.
func (km *AesGcmKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
  if len(serializedKey) == 0 {
    return nil, errInvalidAesGcmKey
  }
  key := new(gcmpb.AesGcmKey)
  if err := proto.Unmarshal(serializedKey, key); err != nil {
    return nil, errInvalidAesGcmKey
  }
  return km.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKey creates an AesGcm subtle for the given AesGcmKey proto.
func (km *AesGcmKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
  key, ok := m.(*gcmpb.AesGcmKey)
  if !ok {
    return nil, errInvalidAesGcmKey
  }
  if err := km.validateKey(key); err != nil {
    return nil, err
  }
  ret, err := aes.NewAesGcm(key.KeyValue)
  if err != nil {
    return nil, fmt.Errorf("aes_gcm_key_manager: cannot create new primitive: %s", err)
  }
  return ret, nil
}

// NewKeyFromSerializedKeyFormat creates a new key according to specification
// the given serialized AesGcmKeyFormat.
func (km *AesGcmKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
  if len(serializedKeyFormat) == 0 {
    return nil, errInvalidAesGcmKeyFormat
  }
  keyFormat := new(gcmpb.AesGcmKeyFormat)
  if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
    return nil, errInvalidAesGcmKeyFormat
  }
  return km.NewKeyFromKeyFormat(keyFormat)
}

// NewKeyFromKeyFormat creates a new key according to specification in the
// given AesGcmKeyFormat.
func (km *AesGcmKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
  keyFormat, ok := m.(*gcmpb.AesGcmKeyFormat)
  if !ok {
    return nil, errInvalidAesGcmKeyFormat
  }
  if err := km.validateKeyFormat(keyFormat); err != nil {
    return nil, fmt.Errorf("aes_gcm_key_manager: invalid key format: %s", err)
  }
  keyValue := random.GetRandomBytes(keyFormat.KeySize)
  return &gcmpb.AesGcmKey{
    Version: AES_GCM_KEY_VERSION,
    Params: keyFormat.Params,
    KeyValue: keyValue,
  }, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized AesGcmKeyFormat. It should be used solely by the key management API.
func (km *AesGcmKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
  key, err := km.NewKeyFromSerializedKeyFormat(serializedKeyFormat)
  if err != nil {
    return nil, err
  }
  serializedKey, err := proto.Marshal(key)
  if err != nil {
    return nil, err
  }
  return &tinkpb.KeyData{
    TypeUrl: AES_GCM_TYPE_URL,
    Value: serializedKey,
    KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
  }, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (_ *AesGcmKeyManager) DoesSupport(typeUrl string) bool {
  return typeUrl == AES_GCM_TYPE_URL
}

// GetKeyType returns the key type of keys managed by this key manager.
func (_ *AesGcmKeyManager) GetKeyType() string {
  return AES_GCM_TYPE_URL
}

// validateKey validates the given AesGcmKey.
func (_ *AesGcmKeyManager) validateKey(key *gcmpb.AesGcmKey) error {
  err := util.ValidateVersion(key.Version, AES_GCM_KEY_VERSION)
  if err != nil {
    return fmt.Errorf("aes_gcm_key_manager: %s", err)
  }
  keySize := uint32(len(key.KeyValue))
  if err := aes.ValidateAesKeySize(keySize); err != nil {
    return fmt.Errorf("aes_gcm_key_manager: %s", err)
  }
  return nil
}

// validateKeyFormat validates the given AesGcmKeyFormat.
func (_ *AesGcmKeyManager) validateKeyFormat(format *gcmpb.AesGcmKeyFormat) error {
  if err := aes.ValidateAesKeySize(format.KeySize); err != nil {
    return fmt.Errorf("aes_gcm_key_manager: %s", err)
  }
  return nil
}