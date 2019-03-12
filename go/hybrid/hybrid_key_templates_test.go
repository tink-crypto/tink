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

package hybrid

import (
	"bytes"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/proto/common_go_proto"
	eciespb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestECIESHKDFAES128GCMKeyTemplate(t *testing.T) {
	kformat := new(eciespb.EciesAeadHkdfKeyFormat)
	kt := ECIESHKDFAES128GCMKeyTemplate()
	if kt.TypeUrl != eciesAEADHKDFPrivateKeyTypeURL {
		t.Error("type url mismatch")
	}
	if kt.OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Error("tink output prefix mismatch")
	}
	if err := proto.Unmarshal(kt.Value, kformat); err != nil {
		t.Error("output format")
	}
	if kformat.Params.KemParams.CurveType != commonpb.EllipticCurveType_NIST_P256 {
		t.Error("EC Curve mismatch")
	}
	if kformat.Params.KemParams.HkdfHashType != commonpb.HashType_SHA256 {
		t.Error("Hash type mismatch")
	}
	if !bytes.Equal(kformat.Params.KemParams.HkdfSalt, []byte{}) {
		t.Error("salt mismatch")
	}
	if strings.Compare(kformat.Params.DemParams.AeadDem.String(), aead.AES128GCMKeyTemplate().String()) != 0 {
		t.Error("AEAD DEM mismatch")
	}
	if kformat.Params.EcPointFormat != commonpb.EcPointFormat_UNCOMPRESSED {
		t.Error("point format mismatch")
	}
}

func TestECIESHKDFAES128CTRHMACSHA256KeyTemplate(t *testing.T) {
	kformat := new(eciespb.EciesAeadHkdfKeyFormat)
	kt := ECIESHKDFAES128CTRHMACSHA256KeyTemplate()
	if kt.TypeUrl != eciesAEADHKDFPrivateKeyTypeURL {
		t.Error("type url mismatch")
	}
	if kt.OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Error("tink output prefix mismatch")
	}
	if err := proto.Unmarshal(kt.Value, kformat); err != nil {
		t.Error("output format")
	}
	if kformat.Params.KemParams.CurveType != commonpb.EllipticCurveType_NIST_P256 {
		t.Error("EC Curve mismatch")
	}
	if kformat.Params.KemParams.HkdfHashType != commonpb.HashType_SHA256 {
		t.Error("Hash type mismatch")
	}
	if !bytes.Equal(kformat.Params.KemParams.HkdfSalt, []byte{}) {
		t.Error("salt mismatch")
	}
	if strings.Compare(kformat.Params.DemParams.AeadDem.String(), aead.AES128CTRHMACSHA256KeyTemplate().String()) != 0 {
		t.Error("AEAD DEM mismatch")
	}
	if kformat.Params.EcPointFormat != commonpb.EcPointFormat_UNCOMPRESSED {
		t.Error("point format mismatch")
	}
}
