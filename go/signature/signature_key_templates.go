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
	"github.com/golang/protobuf/proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplate for PublicKeySign and PublicKeyVerify.
// One can use these templates to generate new Keyset, using utility functions
// in either cleartext_keyset_handle or encrypted_keyset_handle.

// EcdsaP256KeyTemplate is a KeyTemplate of EcdsaPrivateKey with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
func EcdsaP256KeyTemplate() *tinkpb.KeyTemplate {
	return createEcdsaKeyTemplate(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER)
}

// EcdsaP384KeyTemplate is a KeyTemplate of EcdsaPrivateKey with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: DER
func EcdsaP384KeyTemplate() *tinkpb.KeyTemplate {
	return createEcdsaKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER)
}

// EcdsaP521KeyTemplate is a KeyTemplate of EcdsaPrivateKey with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: DER
func EcdsaP521KeyTemplate() *tinkpb.KeyTemplate {
	return createEcdsaKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		ecdsapb.EcdsaSignatureEncoding_DER)
}

// createEcdsaKeyTemplate creates a KeyTemplate containing a EcdasKeyFormat
// with the given parameters.
func createEcdsaKeyTemplate(hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding) *tinkpb.KeyTemplate {
	params := NewEcdsaParams(hashType, curve, encoding)
	format := NewEcdsaKeyFormat(params)
	serializedFormat, _ := proto.Marshal(format)
	return &tinkpb.KeyTemplate{
		TypeUrl: EcdsaSignTypeURL,
		Value:   serializedFormat,
	}
}
