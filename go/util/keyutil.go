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

// ValidateVersion checks whether the given version is valid. The version is valid
// only if it is the range [0..maxExpected]
func ValidateVersion(version uint32, maxExpected uint32) error {
  if version > maxExpected {
    msg := fmt.Sprintf("key has version %v; " +
        "only keys with version in range [0..%v] are supported",
        version, maxExpected)
    return fmt.Errorf("subtle/util: " + msg)
  }
  return nil
}

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

/**
 * Validates the given key set.
 * Returns nil if it is valid; an error otherwise.
 */
// TODO(thaidn): use TypeLiteral to ensure that all keys are of the same primitive.
func ValidateKeyset(keyset *tinkpb.Keyset) error {
  if keyset == nil {
    return fmt.Errorf("keyutil: ValidateKeyset() called with nil")
  }
  if len(keyset.Key) == 0 {
    return fmt.Errorf("keyutil: empty keyset")
  }
  primaryKeyId := keyset.PrimaryKeyId
  hasPrimaryKey := false
  for _, key := range keyset.Key {
    if err := ValidateKey(key); err != nil {
      return err
    }
    if key.Status == tinkpb.KeyStatusType_ENABLED && key.KeyId == primaryKeyId {
      if hasPrimaryKey {
        return fmt.Errorf("keyutil: keyset contains multiple primary keys")
      }
      hasPrimaryKey = true
    }
  }
  if !hasPrimaryKey {
    return fmt.Errorf("keyutil: keyset does not contain a valid primary key")
  }
  return nil
}

/**
 * Validates the given key.
 * Returns nil if it is valid; an error otherwise
 */
func ValidateKey(key *tinkpb.Keyset_Key) error {
  if key == nil {
    return fmt.Errorf("keyutil: ValidateKey() called with nil")
  }
  if key.KeyId <= 0 {
    return fmt.Errorf("keyutil: key has non-positive key id: %d", key.KeyId)
  }
  if key.KeyData == nil {
    return fmt.Errorf("keyutil: key %d has no key data", key.KeyId)
  }
  if key.OutputPrefixType != tinkpb.OutputPrefixType_TINK &&
      key.OutputPrefixType != tinkpb.OutputPrefixType_LEGACY &&
      key.OutputPrefixType != tinkpb.OutputPrefixType_RAW &&
      key.OutputPrefixType != tinkpb.OutputPrefixType_CRUNCHY {
    return fmt.Errorf("keyutil: key %d has unknown prefix", key.KeyId)
  }
  if key.Status != tinkpb.KeyStatusType_ENABLED &&
      key.Status != tinkpb.KeyStatusType_DISABLED &&
      key.Status != tinkpb.KeyStatusType_DESTROYED {
    return fmt.Errorf("keyutil: key %d has unknown status", key.KeyId)
  }
  return nil
}