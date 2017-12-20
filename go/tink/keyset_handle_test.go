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
package tink

import (
  "testing"
  "github.com/google/tink/go/signature/signature"
  "github.com/google/tink/go/util/util"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestNewKeysetHandleBasic(t *testing.T) {
  keyData := util.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
  key := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
  keyset := util.NewKeyset(1, []*tinkpb.Keyset_Key{key})
  keysetInfo, _ := util.GetKeysetInfo(keyset)
  encryptedKeyset := util.NewEncryptedKeyset([]byte{1}, keysetInfo)
  h, err := newKeysetHandle(keyset, encryptedKeyset)
  if err != nil {
    t.Errorf("unexpected error when creating new KeysetHandle")
  }
  // test Keyset()
  if h.Keyset() != keyset {
    t.Errorf("Keyset() returns incorrect value")
  }
  // test EncryptedKeyset()
  if h.EncryptedKeyset() != encryptedKeyset {
    t.Errorf("EncryptedKeyset() returns incorrect value")
  }
  // test KeysetInfo()
  tmp, _ := h.KeysetInfo()
  if tmp.String() != keysetInfo.String() {
    t.Errorf("KeysetInfo() returns incorrect value")
  }
  // test String()
  if h.String() != keysetInfo.String() {
    t.Errorf("String() returns incorrect value")
  }
}

func TestNewKeysetHandleWithInvalidInput(t *testing.T) {
  if _, err := newKeysetHandle(nil, nil); err == nil {
    t.Errorf("NewKeysetHandle should not accept nil as Keyset")
  }
  if _, err := newKeysetHandle(new(tinkpb.Keyset), nil); err == nil {
    t.Errorf("unexpected error: %s", err)
  }
}


func TestGetPublicKeysetHandleBasic(t *testing.T) {
  Registry().RegisterKeyManager(signature.NewEcdsaSignKeyManager())
  Registry().RegisterKeyManager(signature.NewEcdsaVerifyKeyManager())

  template := signature.EcdsaP256KeyTemplate()
  privHandle, err := CleartextKeysetHandle().GenerateNew(template)
  if err != nil {
    t.Errorf("unexpected error: %s", err)
  }
  privKeyset := privHandle.keyset
  pubHandle, err := privHandle.GetPublicKeysetHandle()
  if err != nil {
    t.Errorf("getting public keyset handle failed: %s", err)
  }
  pubKeyset := pubHandle.keyset
  // check Keyset's params
  if len(pubKeyset.Key) != 1 {
    t.Errorf("incorrect number of keys in the keyset handle: %s", len(pubHandle.keyset.Key))
  }
  if pubKeyset.PrimaryKeyId != privKeyset.PrimaryKeyId {
    t.Errorf("incorrect primary key id")
  }
  // check Keyset_Key's params
  pubKey := pubKeyset.Key[0]
  privKey := privKeyset.Key[0]
  if pubKey.OutputPrefixType != privKey.OutputPrefixType {
    t.Errorf("incorrect output prefix type")
  }
  if pubKey.Status != privKey.Status {
    t.Errorf("incorrect key status")
  }
  if pubKey.KeyId != privKey.KeyId {
    t.Errorf("incorrect key id")
  }
  // check KeyData's params
  pubKeyData := pubKey.KeyData
  if pubKeyData.TypeUrl != signature.ECDSA_VERIFY_TYPE_URL {
    t.Errorf("incorrect typeurl")
  }
  if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
    t.Errorf("incorrect key material type")
  }
}