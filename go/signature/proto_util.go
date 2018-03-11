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
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
)

// NewEcdsaPrivateKey creates a EcdsaPrivateKey with the specified paramaters.
func NewEcdsaPrivateKey(version uint32,
	publicKey *ecdsapb.EcdsaPublicKey,
	keyValue []byte) *ecdsapb.EcdsaPrivateKey {
	return &ecdsapb.EcdsaPrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

// NewEcdsaPublicKey creates a EcdsaPublicKey with the specified paramaters.
func NewEcdsaPublicKey(version uint32,
	params *ecdsapb.EcdsaParams,
	x []byte, y []byte) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}

// NewEcdsaParams creates a EcdsaParams with the specified parameters.
func NewEcdsaParams(hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding) *ecdsapb.EcdsaParams {
	return &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
}

// NewEcdsaKeyFormat creates a EcdsaKeyFormat with the specified parameters.
func NewEcdsaKeyFormat(params *ecdsapb.EcdsaParams) *ecdsapb.EcdsaKeyFormat {
	return &ecdsapb.EcdsaKeyFormat{Params: params}
}

// GetEcdsaSignatureEncodingName returns the name of the EcdsaSignatureEncoding.
func GetEcdsaSignatureEncodingName(encoding ecdsapb.EcdsaSignatureEncoding) string {
	ret := ecdsapb.EcdsaSignatureEncoding_name[int32(encoding)]
	return ret
}

// GetEcdsaParamNames returns the string representations of each parameter in
// the given EcdsaParams.
func GetEcdsaParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := tink.GetHashName(params.HashType)
	curveName := tink.GetCurveName(params.Curve)
	encodingName := GetEcdsaSignatureEncodingName(params.Encoding)
	return hashName, curveName, encodingName
}
