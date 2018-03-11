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
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	subtleSig "github.com/google/tink/go/subtle/signature"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/proto/common_go_proto"
)

func TestNewEcdsaVerifyKeyManager(t *testing.T) {
	var km *signature.EcdsaVerifyKeyManager = signature.NewEcdsaVerifyKeyManager()
	if km == nil {
		t.Errorf("NewEcdsaVerifyKeyManager returns nil")
	}
}

func TestEcdsaVerifyGetPrimitiveBasic(t *testing.T) {
	testParams := genValidEcdsaParams()
	km := signature.NewEcdsaVerifyKeyManager()
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewEcdsaPublicKey(testParams[i].hashType, testParams[i].curve)
		tmp, err := km.GetPrimitiveFromKey(key)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		var _ *subtleSig.EcdsaVerify = tmp.(*subtleSig.EcdsaVerify)

		serializedKey, _ := proto.Marshal(key)
		tmp, err = km.GetPrimitiveFromSerializedKey(serializedKey)
		if err != nil {
			t.Errorf("unexpect error in test case %d: %s ", i, err)
		}
		var _ *subtleSig.EcdsaVerify = tmp.(*subtleSig.EcdsaVerify)
	}
}

func TestEcdsaVerifyGetPrimitiveWithInvalidInput(t *testing.T) {
	testParams := genInvalidEcdsaParams()
	km := signature.NewEcdsaVerifyKeyManager()
	for i := 0; i < len(testParams); i++ {
		key := testutil.NewEcdsaPrivateKey(testParams[i].hashType, testParams[i].curve)
		if _, err := km.GetPrimitiveFromKey(key); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
		serializedKey, _ := proto.Marshal(key)
		if _, err := km.GetPrimitiveFromSerializedKey(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// invalid version
	key := testutil.NewEcdsaPublicKey(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256)
	key.Version = signature.EcdsaVerifyKeyVersion + 1
	if _, err := km.GetPrimitiveFromKey(key); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.GetPrimitiveFromKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.GetPrimitiveFromSerializedKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.GetPrimitiveFromSerializedKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}
