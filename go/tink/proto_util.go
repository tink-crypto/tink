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
	. "github.com/google/tink/proto/common_proto"
	. "github.com/google/tink/proto/tink_proto"
)

// Utilities for Key Protos
func NewKeyData(typeUrl string,
	value []byte,
	materialType KeyData_KeyMaterialType) *KeyData {
	return &KeyData{
		TypeUrl:         typeUrl,
		Value:           value,
		KeyMaterialType: materialType,
	}
}

func NewKey(keyData *KeyData,
	status KeyStatusType,
	keyId uint32,
	prefixType OutputPrefixType) *Keyset_Key {
	return &Keyset_Key{
		KeyData:          keyData,
		Status:           status,
		KeyId:            keyId,
		OutputPrefixType: prefixType,
	}
}

func NewKeyset(primaryKeyId uint32,
	keys []*Keyset_Key) *Keyset {
	return &Keyset{
		PrimaryKeyId: primaryKeyId,
		Key:          keys,
	}
}

func NewEncryptedKeyset(encryptedKeySet []byte, info *KeysetInfo) *EncryptedKeyset {
	return &EncryptedKeyset{
		EncryptedKeyset: encryptedKeySet,
		KeysetInfo:      info,
	}
}

// utilities for converting proto types to strings
func GetHashName(hashType HashType) string {
	ret, _ := HashType_name[int32(hashType)]
	return ret
}

func GetCurveName(curve EllipticCurveType) string {
	ret, _ := EllipticCurveType_name[int32(curve)]
	return ret
}
