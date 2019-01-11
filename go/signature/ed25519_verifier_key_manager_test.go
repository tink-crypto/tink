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
	"github.com/google/tink/go/tink"
)

func TestED25519VerifyGetPrimitiveBasic(t *testing.T) {
	km, err := tink.GetKeyManager(signature.ED25519VerifierTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Verifier key manager: %s", err)
	}
	serializedKey, _ := proto.Marshal(testutil.NewED25519PublicKey())
	tmp, err := km.Primitive(serializedKey)
	if err != nil {
		t.Errorf("unexpect error in test case: %s ", err)
	}
	var _ *subtleSig.ED25519Verifier = tmp.(*subtleSig.ED25519Verifier)
}

func TestED25519VerifyGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := tink.GetKeyManager(signature.ED25519VerifierTypeURL)
	if err != nil {
		t.Errorf("cannot obtain ED25519Verifier key manager: %s", err)
	}

	// invalid version
	key := testutil.NewED25519PublicKey()
	key.Version = signature.ED25519VerifierKeyVersion + 1
	serializedKey, _ := proto.Marshal(key)
	if _, err := km.Primitive(serializedKey); err == nil {
		t.Errorf("expect an error when version is invalid")
	}
	// nil input
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}
