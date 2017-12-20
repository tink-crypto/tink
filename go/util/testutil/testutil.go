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
package testutil

import (
  "fmt"
  "crypto/ecdsa"
  "crypto/rand"
  "github.com/google/tink/go/subtle/random"
  "github.com/google/tink/go/util/util"
  "github.com/google/tink/go/subtle/subtleutil"
  "github.com/google/tink/go/tink/tink"
  "github.com/google/tink/go/mac/mac"
  "github.com/google/tink/go/aead/aead"
  "github.com/google/tink/go/signature/signature"
  "github.com/golang/protobuf/proto"
  . "github.com/google/tink/proto/tink_go_proto"
  . "github.com/google/tink/proto/hmac_go_proto"
  . "github.com/google/tink/proto/common_go_proto"
  . "github.com/google/tink/proto/aes_gcm_go_proto"
  . "github.com/google/tink/proto/ecdsa_go_proto"
)

// DummyAeadKeyManager is a dummy implementation of the KeyManager interface.
// It returns DummyAead when GetPrimitive() functions are called.
type DummyAeadKeyManager struct {}
var _ tink.KeyManager = (*DummyAeadKeyManager)(nil)

func (_ *DummyAeadKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
  return new(DummyAead), nil
}
func (_ *DummyAeadKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
  return new(DummyAead), nil
}
func (_ *DummyAeadKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
  return nil, fmt.Errorf("not implemented")
}
func (_ *DummyAeadKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
  return nil, fmt.Errorf("not implemented")
}
func (_ *DummyAeadKeyManager) NewKeyData(serializedKeyFormat []byte) (*KeyData, error) {
  return nil, fmt.Errorf("not implemented")
}
func (_ *DummyAeadKeyManager) DoesSupport(typeUrl string) bool {
  return typeUrl == aead.AES_GCM_TYPE_URL
}
func (_ *DummyAeadKeyManager) GetKeyType() string {
  return aead.AES_GCM_TYPE_URL
}


// DummyAead is a dummy implementation of Aead interface.
type DummyAead struct {}

func (_ *DummyAead) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
  return nil, fmt.Errorf("dummy aead encrypt")
}

func (_ *DummyAead) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
  return nil, fmt.Errorf("dummy aead decrypt")
}

// DummyMac is a dummy implementation of Mac interface.
type DummyMac struct {
  Name string
}

func (h *DummyMac) ComputeMac(data []byte) ([]byte, error) {
  var m []byte
  m = append(m, data...)
  m = append(m, h.Name...)
  return m, nil
}

func (h *DummyMac) VerifyMac(mac []byte, data []byte) (bool, error) {
  return true, nil
}

func NewTestAesGcmKeyset(primaryOutputPrefixType OutputPrefixType) *Keyset {
  keyData := NewAesGcmKeyData(16)
  return NewTestKeyset(keyData, primaryOutputPrefixType)
}

func NewTestHmacKeyset(tagSize uint32,
                      primaryOutputPrefixType OutputPrefixType) *Keyset {
  keyData := NewHmacKeyData(HashType_SHA256, tagSize)
  return NewTestKeyset(keyData, primaryOutputPrefixType)
}

func NewTestKeyset(keyData *KeyData,
                  primaryOutputPrefixType OutputPrefixType) *Keyset {
  primaryKey := util.NewKey(keyData, KeyStatusType_ENABLED, 42, primaryOutputPrefixType)
  rawKey := util.NewKey(keyData, KeyStatusType_ENABLED, 43, OutputPrefixType_RAW)
  legacyKey := util.NewKey(keyData, KeyStatusType_ENABLED, 44, OutputPrefixType_LEGACY)
  tinkKey := util.NewKey(keyData, KeyStatusType_ENABLED, 45, OutputPrefixType_TINK)
  crunchyKey := util.NewKey(keyData, KeyStatusType_ENABLED, 46, OutputPrefixType_CRUNCHY)
  keys := []*Keyset_Key{primaryKey, rawKey, legacyKey, tinkKey, crunchyKey}
  return util.NewKeyset(primaryKey.KeyId, keys)
}

func NewDummyKey(keyId int, status KeyStatusType, outputPrefixType OutputPrefixType) *Keyset_Key {
  return &Keyset_Key{
    KeyData: new(KeyData),
    Status: status,
    KeyId: uint32(keyId),
    OutputPrefixType: outputPrefixType,
  }
}

func NewEcdsaPrivateKey(hashType HashType, curve EllipticCurveType) *EcdsaPrivateKey {
  curveName, _ := EllipticCurveType_name[int32(curve)]
  priv, _ := ecdsa.GenerateKey(subtleutil.GetCurve(curveName), rand.Reader)
  params := util.NewEcdsaParams(hashType,
                                curve,
                                EcdsaSignatureEncoding_DER)
  publicKey := util.NewEcdsaPublicKey(signature.ECDSA_VERIFY_KEY_VERSION,
                                      params, priv.X.Bytes(), priv.Y.Bytes())
  return util.NewEcdsaPrivateKey(signature.ECDSA_SIGN_KEY_VERSION,
                                publicKey, priv.D.Bytes())
}

func NewEcdsaPrivateKeyData(hashType HashType, curve EllipticCurveType) *KeyData {
  key := NewEcdsaPrivateKey(hashType, curve)
  serializedKey, _ := proto.Marshal(key)
  return &KeyData{
    TypeUrl: signature.ECDSA_SIGN_TYPE_URL,
    Value: serializedKey,
    KeyMaterialType: KeyData_ASYMMETRIC_PRIVATE,
  }
}

func NewEcdsaPublicKey(hashType HashType, curve EllipticCurveType) *EcdsaPublicKey {
  return NewEcdsaPrivateKey(hashType, curve).PublicKey
}

func NewAesGcmKey(keySize uint32) *AesGcmKey {
  keyValue := random.GetRandomBytes(keySize)
  return util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION, keyValue)
}

func NewAesGcmKeyData(keySize uint32) *KeyData{
  keyValue := random.GetRandomBytes(keySize)
  key := util.NewAesGcmKey(aead.AES_GCM_KEY_VERSION, keyValue)
  serializedKey, _ := proto.Marshal(key)
  return util.NewKeyData(aead.AES_GCM_TYPE_URL, serializedKey, KeyData_SYMMETRIC)
}

func NewSerializedAesGcmKey(keySize uint32) []byte {
  key := NewAesGcmKey(keySize)
  serializedKey, err := proto.Marshal(key)
  if err != nil {
    panic(fmt.Sprintf("cannot marshal AesGcmKey: %s", err))
  }
  return serializedKey
}

func NewHmacKey(hashType HashType, tagSize uint32) *HmacKey {
  params := util.NewHmacParams(hashType, tagSize)
  keyValue := random.GetRandomBytes(20)
  return util.NewHmacKey(params, mac.HMAC_KEY_VERSION, keyValue)
}

func NewHmacKeyFormat(hashType HashType, tagSize uint32) *HmacKeyFormat {
  params := util.NewHmacParams(hashType, tagSize)
  keySize := uint32(20)
  return util.NewHmacKeyFormat(params, keySize)
}

func NewHmacKeysetManager() *tink.KeysetManager {
  macTemplate := mac.HmacSha256Tag128KeyTemplate()
  manager := tink.NewKeysetManager(macTemplate, nil, nil)
  err := manager.Rotate()
  if err != nil {
    panic(fmt.Sprintf("cannot rotate keyset manager: %s", err))
  }
  return manager
}

func NewHmacKeyData(hashType HashType, tagSize uint32) *KeyData {
  key := NewHmacKey(hashType, tagSize)
  serializedKey, _ := proto.Marshal(key)
  return &KeyData{
    TypeUrl: mac.HMAC_TYPE_URL,
    Value: serializedKey,
    KeyMaterialType: KeyData_SYMMETRIC,
  }
}