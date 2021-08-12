// Copyright 2018 Google LLC
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
	"google.golang.org/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplates for Signer and Verifier.
// One can use these templates to generate new Keysets.

// ECDSAP256KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP256KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP256KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
//   - Output prefix type: RAW
func ECDSAP256KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// ECDSAP384KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP384KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP384KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Output prefix type: RAW
func ECDSAP384KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// ECDSAP521KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP521KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP521KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP521KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// createECDSAKeyTemplate creates a KeyTemplate containing a EcdasKeyFormat
// with the given parameters.
func createECDSAKeyTemplate(hashType commonpb.HashType, curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding, prefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	params := &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
	format := &ecdsapb.EcdsaKeyFormat{Params: params}
	serializedFormat, _ := proto.Marshal(format)
	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdsaSignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: prefixType,
	}
}

// ED25519KeyTemplate is a KeyTemplate that generates a new ED25519 private key.
func ED25519KeyTemplate() *tinkpb.KeyTemplate {
	return &tinkpb.KeyTemplate{
		TypeUrl:          ed25519SignerTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

// ED25519KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ED25519 private key.
func ED25519KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return &tinkpb.KeyTemplate{
		TypeUrl:          ed25519SignerTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
