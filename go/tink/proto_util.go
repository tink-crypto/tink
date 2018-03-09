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
	commonpb "github.com/google/tink/proto/common_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// NewKeyData creates a new KeyData with the specified parameters.
func NewKeyData(typeURL string,
	value []byte,
	materialType tinkpb.KeyData_KeyMaterialType) *tinkpb.KeyData {
	return &tinkpb.KeyData{
		TypeUrl:         typeURL,
		Value:           value,
		KeyMaterialType: materialType,
	}
}

// NewKey creates a new Key with the specified parameters.
func NewKey(keyData *tinkpb.KeyData,
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

// NewKeyset creates a new Keyset with the specified parameters.
func NewKeyset(primaryKeyID uint32,
	keys []*tinkpb.Keyset_Key) *tinkpb.Keyset {
	return &tinkpb.Keyset{
		PrimaryKeyId: primaryKeyID,
		Key:          keys,
	}
}

// NewEncryptedKeyset creates a new EncryptedKeyset with a specified parameters.
func NewEncryptedKeyset(encryptedKeySet []byte, info *tinkpb.KeysetInfo) *tinkpb.EncryptedKeyset {
	return &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encryptedKeySet,
		KeysetInfo:      info,
	}
}

// GetHashName returns the name of the HashType.
func GetHashName(hashType commonpb.HashType) string {
	return commonpb.HashType_name[int32(hashType)]
}

// GetCurveName returns the name of the EllipticCurveType.
func GetCurveName(curve commonpb.EllipticCurveType) string {
	return commonpb.EllipticCurveType_name[int32(curve)]
}
