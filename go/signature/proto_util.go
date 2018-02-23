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

package signature

import (
	"github.com/google/tink/go/tink"
	. "github.com/google/tink/proto/common_proto"
	. "github.com/google/tink/proto/ecdsa_proto"
)

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

func GetEcdsaSignatureEncodingName(encoding EcdsaSignatureEncoding) string {
	ret := EcdsaSignatureEncoding_name[int32(encoding)]
	return ret
}

// GetEcdsaParamNames returns the string representations of each parameter in
// the given EcdsaParams
func GetEcdsaParamNames(params *EcdsaParams) (string, string, string) {
	hashName := tink.GetHashName(params.HashType)
	curveName := tink.GetCurveName(params.Curve)
	encodingName := GetEcdsaSignatureEncodingName(params.Encoding)
	return hashName, curveName, encodingName
}
