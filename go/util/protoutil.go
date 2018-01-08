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
	. "github.com/google/tink/proto/aes_gcm_go_proto"
	. "github.com/google/tink/proto/common_go_proto"
	. "github.com/google/tink/proto/ecdsa_go_proto"
	. "github.com/google/tink/proto/hmac_go_proto"
	. "github.com/google/tink/proto/tink_go_proto"
)

// Utilities for Hmac Protos
func NewHmacParams(hashType HashType, tagSize uint32) *HmacParams {
	return &HmacParams{
		Hash:    hashType,
		TagSize: tagSize,
	}
}

func NewHmacKey(params *HmacParams, version uint32, keyValue []byte) *HmacKey {
	return &HmacKey{
		Version:  version,
		Params:   params,
		KeyValue: keyValue,
	}
}

func NewHmacKeyFormat(params *HmacParams, keySize uint32) *HmacKeyFormat {
	return &HmacKeyFormat{
		Params:  params,
		KeySize: keySize,
	}
}

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

// Utilities for AesGcm protos
func NewAesGcmKey(version uint32, keyValue []byte) *AesGcmKey {
	return &AesGcmKey{
		Version:  version,
		KeyValue: keyValue,
	}
}

func NewAesGcmKeyFormat(keySize uint32) *AesGcmKeyFormat {
	return &AesGcmKeyFormat{
		KeySize: keySize,
	}
}

// Utilities for Ecdsa protos
func NewEcdsaPrivateKey(version uint32,
	publicKey *EcdsaPublicKey,
	keyValue []byte) *EcdsaPrivateKey {
	return &EcdsaPrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

func NewEcdsaPublicKey(version uint32,
	params *EcdsaParams,
	x []byte, y []byte) *EcdsaPublicKey {
	return &EcdsaPublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}

func NewEcdsaParams(hashType HashType,
	curve EllipticCurveType,
	encoding EcdsaSignatureEncoding) *EcdsaParams {
	return &EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
}

func NewEcdsaKeyFormat(params *EcdsaParams) *EcdsaKeyFormat {
	return &EcdsaKeyFormat{Params: params}
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

func GetEncodingName(encoding EcdsaSignatureEncoding) string {
	ret, _ := EcdsaSignatureEncoding_name[int32(encoding)]
	return ret
}

// GetEcdsaParamNames returns the string representations of each parameter in
// the given EcdsaParams
func GetEcdsaParamNames(params *EcdsaParams) (string, string, string) {
	hashName := GetHashName(params.HashType)
	curveName := GetCurveName(params.Curve)
	encodingName := GetEncodingName(params.Encoding)
	return hashName, curveName, encodingName
}
