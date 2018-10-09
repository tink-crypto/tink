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
	"errors"
	"fmt"

	commonpb "github.com/google/tink/proto/common_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// ValidateVersion checks whether the given version is valid. The version is valid
// only if it is the range [0..maxExpected]
func ValidateVersion(version, maxExpected uint32) error {
	if version > maxExpected {
		return fmt.Errorf("key has version %v; only keys with version in range [0..%v] are supported",
			version, maxExpected)
	}
	return nil
}

// GetHashName returns the name of the HashType.
func GetHashName(hashType commonpb.HashType) string {
	return commonpb.HashType_name[int32(hashType)]
}

// GetCurveName returns the name of the EllipticCurveType.
func GetCurveName(curve commonpb.EllipticCurveType) string {
	return commonpb.EllipticCurveType_name[int32(curve)]
}

// GetKeysetInfo returns a KeysetInfo from a Keyset protobuf.
func GetKeysetInfo(keyset *tinkpb.Keyset) (*tinkpb.KeysetInfo, error) {
	if keyset == nil {
		return nil, errors.New("Gettinkpb.KeysetInfo() called with nil")
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
		KeyInfo:      keyInfos,
	}, nil
}

// GetKeyInfo returns a KeyInfo from a Key protobuf.
func GetKeyInfo(key *tinkpb.Keyset_Key) (*tinkpb.KeysetInfo_KeyInfo, error) {
	if key == nil {
		return nil, errors.New("GetKeyInfo() called with nil")
	}
	return &tinkpb.KeysetInfo_KeyInfo{
		TypeUrl:          key.KeyData.TypeUrl,
		Status:           key.Status,
		KeyId:            key.KeyId,
		OutputPrefixType: key.OutputPrefixType,
	}, nil
}

// ValidateKeyset validates the given key set.
// Returns nil if it is valid; an error otherwise.
func ValidateKeyset(keyset *tinkpb.Keyset) error {
	if keyset == nil {
		return fmt.Errorf("ValidateKeyset() called with nil")
	}
	if len(keyset.Key) == 0 {
		return fmt.Errorf("empty keyset")
	}
	primaryKeyID := keyset.PrimaryKeyId
	hasPrimaryKey := false
	for _, key := range keyset.Key {
		if err := ValidateKey(key); err != nil {
			return err
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED && key.KeyId == primaryKeyID {
			if hasPrimaryKey {
				return fmt.Errorf("keyset contains multiple primary keys")
			}
			hasPrimaryKey = true
		}
	}
	if !hasPrimaryKey {
		return fmt.Errorf("keyset does not contain a valid primary key")
	}
	return nil
}

/*
ValidateKey validates the given key.
Returns nil if it is valid; an error otherwise.
*/
func ValidateKey(key *tinkpb.Keyset_Key) error {
	if key == nil {
		return fmt.Errorf("ValidateKey() called with nil")
	}
	if key.KeyId <= 0 {
		return fmt.Errorf("key has non-positive key id: %d", key.KeyId)
	}
	if key.KeyData == nil {
		return fmt.Errorf("key %d has no key data", key.KeyId)
	}
	if key.OutputPrefixType != tinkpb.OutputPrefixType_TINK &&
		key.OutputPrefixType != tinkpb.OutputPrefixType_LEGACY &&
		key.OutputPrefixType != tinkpb.OutputPrefixType_RAW &&
		key.OutputPrefixType != tinkpb.OutputPrefixType_CRUNCHY {
		return fmt.Errorf("key %d has unknown prefix", key.KeyId)
	}
	if key.Status != tinkpb.KeyStatusType_ENABLED &&
		key.Status != tinkpb.KeyStatusType_DISABLED &&
		key.Status != tinkpb.KeyStatusType_DESTROYED {
		return fmt.Errorf("key %d has unknown status", key.KeyId)
	}
	return nil
}

// CreateKeyData creates a new KeyData with the specified parameters.
func CreateKeyData(typeURL string,
	value []byte,
	materialType tinkpb.KeyData_KeyMaterialType) *tinkpb.KeyData {
	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           value,
		KeyMaterialType: materialType,
	}
}

// CreateKey creates a new Key with the specified parameters.
func CreateKey(keyData *tinkpb.KeyData,
	status tinkpb.KeyStatusType,
	keyID uint32,
	prefixType tinkpb.OutputPrefixType) *tinkpb.Keyset_Key {
	return &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           status,
		KeyId:            keyID,
		OutputPrefixType: prefixType,
	}
}

// CreateKeyset creates a new Keyset with the specified parameters.
func CreateKeyset(primaryKeyID uint32,
	keys []*tinkpb.Keyset_Key) *tinkpb.Keyset {
	return &tinkpb.Keyset{
		PrimaryKeyId: primaryKeyID,
		Key:          keys,
	}
}

// CreateEncryptedKeyset creates a new EncryptedKeyset with a specified parameters.
func CreateEncryptedKeyset(encryptedKeySet []byte, info *tinkpb.KeysetInfo) *tinkpb.EncryptedKeyset {
	return &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encryptedKeySet,
		KeysetInfo:      info,
	}
}
