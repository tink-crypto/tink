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

package signature_test

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestECDSAKeyTemplates(t *testing.T) {
	var flagTests = []struct {
		tcName      string
		typeURL     string
		sigTemplate *tinkpb.KeyTemplate
		curveType   commonpb.EllipticCurveType
		hashType    commonpb.HashType
		sigEncoding ecdsapb.EcdsaSignatureEncoding
		prefixType  tinkpb.OutputPrefixType
	}{
		{
			tcName:      "P-256 with SHA256, DER format and TINK output prefix",
			typeURL:     testutil.ECDSASignerTypeURL,
			sigTemplate: signature.ECDSAP256KeyTemplate(),
			curveType:   commonpb.EllipticCurveType_NIST_P256,
			hashType:    commonpb.HashType_SHA256,
			sigEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
			prefixType:  tinkpb.OutputPrefixType_TINK,
		},
		{
			tcName:      "P-384 with SHA512, DER format and TINK output prefix",
			typeURL:     testutil.ECDSASignerTypeURL,
			sigTemplate: signature.ECDSAP384KeyTemplate(),
			curveType:   commonpb.EllipticCurveType_NIST_P384,
			hashType:    commonpb.HashType_SHA512,
			sigEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
			prefixType:  tinkpb.OutputPrefixType_TINK,
		},
		{
			tcName:      "P-521 with SHA512, DER format and TINK output prefix",
			typeURL:     testutil.ECDSASignerTypeURL,
			sigTemplate: signature.ECDSAP521KeyTemplate(),
			curveType:   commonpb.EllipticCurveType_NIST_P521,
			hashType:    commonpb.HashType_SHA512,
			sigEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
			prefixType:  tinkpb.OutputPrefixType_TINK,
		},
		{
			tcName:      "P-256 with SHA256, DER format and RAW output prefix",
			typeURL:     testutil.ECDSASignerTypeURL,
			sigTemplate: signature.ECDSAP256KeyWithoutPrefixTemplate(),
			curveType:   commonpb.EllipticCurveType_NIST_P256,
			hashType:    commonpb.HashType_SHA256,
			sigEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
			prefixType:  tinkpb.OutputPrefixType_RAW,
		},
		{
			tcName:      "P-384 with SHA512, DER format and RAW output prefix",
			typeURL:     testutil.ECDSASignerTypeURL,
			sigTemplate: signature.ECDSAP384KeyWithoutPrefixTemplate(),
			curveType:   commonpb.EllipticCurveType_NIST_P384,
			hashType:    commonpb.HashType_SHA512,
			sigEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
			prefixType:  tinkpb.OutputPrefixType_RAW,
		},
		{
			tcName:      "P-521 with SHA512, DER format and RAW output prefix",
			typeURL:     testutil.ECDSASignerTypeURL,
			sigTemplate: signature.ECDSAP521KeyWithoutPrefixTemplate(),
			curveType:   commonpb.EllipticCurveType_NIST_P521,
			hashType:    commonpb.HashType_SHA512,
			sigEncoding: ecdsapb.EcdsaSignatureEncoding_DER,
			prefixType:  tinkpb.OutputPrefixType_RAW,
		},
	}

	for _, tt := range flagTests {
		t.Run("test ECDSA - "+tt.tcName, func(t *testing.T) {
			err := checkECDSAKeyTemplate(tt.sigTemplate,
				tt.typeURL,
				tt.hashType,
				tt.curveType,
				tt.sigEncoding,
				tt.prefixType)
			if err != nil {
				t.Errorf("failed %s: %s", tt.tcName, err)
			}
		})
	}
}

func TestED25519KeyTemplates(t *testing.T) {
	var flagTests = []struct {
		tcName      string
		typeURL     string
		sigTemplate *tinkpb.KeyTemplate
		prefixType  tinkpb.OutputPrefixType
	}{
		{
			tcName:      "ED25519 with TINK output prefix",
			typeURL:     testutil.ED25519SignerTypeURL,
			sigTemplate: signature.ED25519KeyTemplate(),
			prefixType:  tinkpb.OutputPrefixType_TINK,
		},
		{
			tcName:      "ED25519 with RAW output prefix",
			typeURL:     testutil.ED25519SignerTypeURL,
			sigTemplate: signature.ED25519KeyWithoutPrefixTemplate(),
			prefixType:  tinkpb.OutputPrefixType_RAW,
		},
	}

	for _, tt := range flagTests {
		t.Run("Test ED25519 - "+tt.tcName, func(t *testing.T) {
			err := checkKeyTypeAndOutputPrefix(tt.sigTemplate,
				tt.typeURL,
				tt.prefixType)
			if err != nil {
				t.Errorf("failed %s: %s", tt.tcName, err)
			}
		})
	}
}

func checkECDSAKeyTemplate(template *tinkpb.KeyTemplate,
	typeURL string,
	hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding,
	prefixType tinkpb.OutputPrefixType) error {
	err := checkKeyTypeAndOutputPrefix(template, typeURL, prefixType)
	if err != nil {
		return err
	}

	format := new(ecdsapb.EcdsaKeyFormat)
	err = proto.Unmarshal(template.Value, format)
	if err != nil {
		return fmt.Errorf("cannot unmarshak key format: %s", err)
	}

	params := format.Params
	if params.HashType != hashType {
		return fmt.Errorf("incorrect hash type: expect %d, got %d", hashType, params.HashType)
	}

	if params.Curve != curve {
		return fmt.Errorf("incorrect curve: expect %d, got %d", curve, params.Curve)
	}

	if params.Encoding != encoding {
		return fmt.Errorf("incorrect encoding: expect %d, got %d", encoding, params.Encoding)
	}

	return nil
}

func checkKeyTypeAndOutputPrefix(template *tinkpb.KeyTemplate,
	typeURL string,
	prefixType tinkpb.OutputPrefixType) error {
	if template.TypeUrl != typeURL {
		return fmt.Errorf("incorrect typeurl: expect %s, got %s", typeURL, template.TypeUrl)
	}

	if template.OutputPrefixType != prefixType {
		return fmt.Errorf("incorrect outputPrefixType: expect: %v, got %v", prefixType, template.OutputPrefixType)
	}

	return nil
}
