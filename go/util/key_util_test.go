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
package test

import (
  "testing"
  "strings"
  "github.com/google/tink/go/util/util"
  "github.com/google/tink/go/subtle/random"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestGetKeyInfo(t *testing.T) {
  _ ,err := util.GetKeyInfo(nil)
  if err == nil {
    t.Errorf("expect an error when input is nil")
  }
  key := newRandomSymmetricKey()
  info, err := util.GetKeyInfo(key)
  if err != nil {
    t.Errorf("unexpected error")
  }
  if !checkKeyInfo(info, key) {
    t.Errorf("KeyInfo mismatched")
  }
  if strings.Contains(info.String(), string(key.KeyData.Value)) {
    t.Errorf("KeyInfo contains key value")
  }
}

func TestGetKeysetInfo(t *testing.T) {
  _ ,err := util.GetKeysetInfo(nil)
  if err == nil {
    t.Errorf("expect an error when input is nil")
  }
  key := newRandomSymmetricKey()
  keyset := util.NewKeyset(1, []*tinkpb.Keyset_Key{key})
  keysetInfo, err := util.GetKeysetInfo(keyset)
  if keysetInfo.PrimaryKeyId != keyset.PrimaryKeyId {
    t.Errorf("PrimaryKeyId mismatched")
  }
  for i, keyInfo := range keysetInfo.KeyInfo {
    if !checkKeyInfo(keyInfo, keyset.Key[i]) {
      t.Errorf("KeyInfo mismatched")
    }
  }
  if strings.Contains(keysetInfo.String(), string(key.KeyData.Value)) {
    t.Errorf("KeysetInfo contains key value")
  }
}

// TODO(thanhb): move this function to testutil.
func newRandomSymmetricKey() *tinkpb.Keyset_Key {
  keyValue := random.GetRandomBytes(16)
  keyData := util.NewKeyData("some url", keyValue, tinkpb.KeyData_SYMMETRIC)
  return util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
}

func checkKeyInfo(info *tinkpb.KeysetInfo_KeyInfo, key *tinkpb.Keyset_Key) bool{
  if info.TypeUrl != key.KeyData.TypeUrl ||
      info.Status != key.Status ||
      info.KeyId != key.KeyId ||
      info.OutputPrefixType != key.OutputPrefixType {
    return false
  }
  return true
}