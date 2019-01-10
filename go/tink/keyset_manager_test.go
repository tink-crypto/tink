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

package tink_test

import (
	"testing"

	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestKeysetManagerBasic(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm := tink.NewKeysetManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	err := ksm.Rotate(kt)
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}
	handle, err := ksm.KeysetHandle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	keyset := handle.Keyset()
	if len(keyset.Key) != 1 {
		t.Errorf("expect the number of keys in the keyset is 1")
	}
	if keyset.Key[0].KeyId != keyset.PrimaryKeyId ||
		keyset.Key[0].KeyData.TypeUrl != mac.HMACTypeURL ||
		keyset.Key[0].Status != tinkpb.KeyStatusType_ENABLED ||
		keyset.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("incorrect key information: %s", keyset.Key[0])
	}
}

func TestExistingKeyset(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm1 := tink.NewKeysetManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	err := ksm1.Rotate(kt)
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}

	handle1, err := ksm1.KeysetHandle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	keyset1 := handle1.Keyset()

	ksm2 := tink.FromKeysetHandle(handle1)
	ksm2.Rotate(kt)
	handle2, err := ksm2.KeysetHandle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	keyset2 := handle2.Keyset()
	if len(keyset2.Key) != 2 {
		t.Errorf("expect the number of keys to be 2, got %d", len(keyset2.Key))
	}
	if keyset1.Key[0].String() != keyset2.Key[0].String() {
		t.Errorf("expect the first key in two keysets to be the same")
	}
	if keyset2.Key[1].KeyId != keyset2.PrimaryKeyId {
		t.Errorf("expect the second key to be primary")
	}
}
