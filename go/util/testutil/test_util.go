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
  "crypto/elliptic"
  "crypto/rand"
  "github.com/google/tink/go/subtle/random"
  "github.com/google/tink/go/util/util"
  // "github.com/google/tink/go/tink/tink"
  // "github.com/google/tink/go/mac/mac"
  "github.com/google/tink/go/aead/aead"
  "github.com/golang/protobuf/proto"
  . "github.com/google/tink/proto/tink_go_proto"
  // . "github.com/google/tink/proto/hmac_go_proto"
  . "github.com/google/tink/proto/common_go_proto"
  . "github.com/google/tink/proto/aes_gcm_go_proto"
  . "github.com/google/tink/proto/ecdsa_go_proto"
)

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

// Return a key set with 4 keys.
func NewTestKeyset(keyData *KeyData,
                  primaryOutputPrefixType OutputPrefixType) *Keyset {
  primaryKey := util.NewKey(keyData, KeyStatusType_ENABLED, 42, primaryOutputPrefixType)
  rawKey := util.NewKey(keyData, KeyStatusType_ENABLED, 43, OutputPrefixType_RAW)
  legacyKey := util.NewKey(keyData, KeyStatusType_ENABLED, 44, OutputPrefixType_LEGACY)
  tinkKey := util.NewKey(keyData, KeyStatusType_ENABLED, 45, OutputPrefixType_TINK)
  keys := []*Keyset_Key{primaryKey, rawKey, legacyKey, tinkKey}
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

func NewP256EcdsaPrivateKey() *EcdsaPrivateKey {
  priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  publicKey := util.NewEcdsaPublicKey(0,
                                HashType_SHA256,
                                EllipticCurveType_NIST_P256,
                                EcdsaSignatureEncoding_DER,
                                priv.X.Bytes(), priv.Y.Bytes())
  return util.NewEcdsaPrivateKey(0, publicKey, priv.D.Bytes())
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