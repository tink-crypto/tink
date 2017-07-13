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
package util

import (
  "fmt"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

/**
 * @return a tinkpb.KeysetInfo-proto from a {@code keyset} protobuf.
 */
func GetKeysetInfo(keyset *tinkpb.Keyset) (*tinkpb.KeysetInfo, error) {
  if keyset == nil {
    return nil, fmt.Errorf("key_util: Gettinkpb.KeysetInfo() called with nil")
  }
  nKey := len(keyset.Key)
  keyInfos := make([]*tinkpb.KeysetInfo_KeyInfo, nKey)
  for i, key := range keyset.Key {
    info, err := GetKeyInfo(key)
    if err != nil {
      return nil, err
    }
    keyInfos[i] = info
  }
  return &tinkpb.KeysetInfo{
    PrimaryKeyId: keyset.PrimaryKeyId,
    KeyInfo: keyInfos,
  }, nil
}


/**
 * @return a KeyInfo-proto from a {@code key} protobuf.
 */
func GetKeyInfo(key *tinkpb.Keyset_Key) (*tinkpb.KeysetInfo_KeyInfo, error) {
  if key == nil {
    return nil, fmt.Errorf("keyutil: GetKeyInfo() called with nil")
  }
  return &tinkpb.KeysetInfo_KeyInfo{
    TypeUrl: key.KeyData.TypeUrl,
    Status: key.Status,
    KeyId: key.KeyId,
    OutputPrefixType: key.OutputPrefixType,
  }, nil
}