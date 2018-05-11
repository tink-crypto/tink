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

package tink

import (
	"testing"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestNewKeysetHandleBasic(t *testing.T) {
	keyData := CreateKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := CreateKeyset(1, []*tinkpb.Keyset_Key{key})
	keysetInfo, _ := GetKeysetInfo(keyset)
	encryptedKeyset := CreateEncryptedKeyset([]byte{1}, keysetInfo)
	h, err := newKeysetHandle(keyset, encryptedKeyset)
	if err != nil {
		t.Errorf("unexpected error when creating new KeysetHandle")
	}
	// test Keyset()
	if h.Keyset() != keyset {
		t.Errorf("Keyset() returns incorrect value")
	}
	// test EncryptedKeyset()
	if h.EncryptedKeyset() != encryptedKeyset {
		t.Errorf("EncryptedKeyset() returns incorrect value")
	}
	// test KeysetInfo()
	tmp, _ := h.KeysetInfo()
	if tmp.String() != keysetInfo.String() {
		t.Errorf("KeysetInfo() returns incorrect value")
	}
	// test String()
	if h.String() != keysetInfo.String() {
		t.Errorf("String() returns incorrect value")
	}
}

func TestNewKeysetHandleWithInvalidInput(t *testing.T) {
	if _, err := newKeysetHandle(nil, nil); err == nil {
		t.Errorf("NewKeysetHandle should not accept nil as Keyset")
	}
	if _, err := newKeysetHandle(new(tinkpb.Keyset), nil); err == nil {
		t.Errorf("unexpected error: %s", err)
	}
}
