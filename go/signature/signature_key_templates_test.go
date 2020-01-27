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
	var template *tinkpb.KeyTemplate
	var err error
	// ECDSA P-256
	template = signature.ECDSAP256KeyTemplate()
	err = checkECDSAKeyTemplate(template,
		commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER)
	if err != nil {
		t.Errorf("invalid ECDSA P-256 key template: %s", err)
	}
	// ECDSA P-384
	template = signature.ECDSAP384KeyTemplate()
	err = checkECDSAKeyTemplate(template,
		commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER)
	if err != nil {
		t.Errorf("invalid ECDSA P-384 key template: %s", err)
	}
	// ECDSA P-521
	template = signature.ECDSAP521KeyTemplate()
	err = checkECDSAKeyTemplate(template,
		commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		ecdsapb.EcdsaSignatureEncoding_DER)
	if err != nil {
		t.Errorf("invalid ECDSA P-521 key template: %s", err)
	}
}

func checkECDSAKeyTemplate(template *tinkpb.KeyTemplate,
	hashType commonpb.HashType,
	curve commonpb.EllipticCurveType,
	encoding ecdsapb.EcdsaSignatureEncoding) error {
	if template.TypeUrl != testutil.ECDSASignerTypeURL {
		return fmt.Errorf("incorrect typeurl: expect %s, got %s", testutil.ECDSASignerTypeURL, template.TypeUrl)
	}
	format := new(ecdsapb.EcdsaKeyFormat)
	if err := proto.Unmarshal(template.Value, format); err != nil {
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
