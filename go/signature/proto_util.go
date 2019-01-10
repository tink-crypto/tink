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
	"golang.org/x/crypto/ed25519"
	"github.com/google/tink/go/tink"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/proto/ed25519_go_proto"
)

// NewECDSAPrivateKey creates a ECDSAPrivateKey with the specified paramaters.
func NewECDSAPrivateKey(version uint32,
	publicKey *ecdsapb.EcdsaPublicKey,
	keyValue []byte) *ecdsapb.EcdsaPrivateKey {
	return &ecdsapb.EcdsaPrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

// NewECDSAPublicKey creates a ECDSAPublicKey with the specified paramaters.
func NewECDSAPublicKey(version uint32,
	params *ecdsapb.EcdsaParams,
	x []byte, y []byte) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}

// NewECDSAParams creates a ECDSAParams with the specified parameters.
func NewECDSAParams(hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding) *ecdsapb.EcdsaParams {
	return &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
}

// NewECDSAKeyFormat creates a ECDSAKeyFormat with the specified parameters.
func NewECDSAKeyFormat(params *ecdsapb.EcdsaParams) *ecdsapb.EcdsaKeyFormat {
	return &ecdsapb.EcdsaKeyFormat{Params: params}
}

// GetECDSASignatureEncodingName returns the name of the ECDSASignatureEncoding.
func GetECDSASignatureEncodingName(encoding ecdsapb.EcdsaSignatureEncoding) string {
	ret := ecdsapb.EcdsaSignatureEncoding_name[int32(encoding)]
	return ret
}

// GetECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
func GetECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := tink.GetHashName(params.HashType)
	curveName := tink.GetCurveName(params.Curve)
	encodingName := GetECDSASignatureEncodingName(params.Encoding)
	return hashName, curveName, encodingName
}

// NewED25519PrivateKey creates a ED25519PrivateKey with the specified paramaters.
func NewED25519PrivateKey(version uint32, publicKey *ed25519pb.Ed25519PublicKey, keyValue *ed25519.PrivateKey) *ed25519pb.Ed25519PrivateKey {
	return &ed25519pb.Ed25519PrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue.Seed(),
	}
}

// NewED25519PublicKey creates a ED25519PublicKey with the specified paramaters.
func NewED25519PublicKey(version uint32, keyValue *ed25519.PublicKey) *ed25519pb.Ed25519PublicKey {
	return &ed25519pb.Ed25519PublicKey{
		Version:  version,
		KeyValue: []byte(*keyValue),
	}
}
