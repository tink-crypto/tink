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

	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestValidateVersion(t *testing.T) {
	if tink.ValidateVersion(2, 1) == nil ||
		tink.ValidateVersion(1, 1) != nil ||
		tink.ValidateVersion(1, 2) != nil {
		t.Errorf("incorrect version validation")
	}
}

func TestGetKeyInfo(t *testing.T) {
	_, err := tink.GetKeyInfo(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
	keyData := tink.NewKeyData("some url", []byte{1}, tinkpb.KeyData_SYMMETRIC)
	key := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	info, err := tink.GetKeyInfo(key)
	if err != nil {
		t.Errorf("unexpected error")
	}
	if !compareKeyInfo(info, key) {
		t.Errorf("KeyInfo mismatched")
	}
}

func TestGetKeysetInfo(t *testing.T) {
	_, err := tink.GetKeysetInfo(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
	keyData := tink.NewKeyData("some url", []byte{1}, tinkpb.KeyData_SYMMETRIC)
	key := tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := tink.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	keysetInfo, err := tink.GetKeysetInfo(keyset)
	if err != nil {
		t.Error("This should not error here")
	}
	if keysetInfo.PrimaryKeyId != keyset.PrimaryKeyId {
		t.Errorf("PrimaryKeyId mismatched")
	}
	for i, keyInfo := range keysetInfo.KeyInfo {
		if !compareKeyInfo(keyInfo, keyset.Key[i]) {
			t.Errorf("KeyInfo mismatched")
		}
	}
}

func TestValidateKey(t *testing.T) {
	invalidKeys := generateInvalidKeys()
	for i, key := range invalidKeys {
		if err := tink.ValidateKey(key); err == nil {
			t.Errorf("expect an error for invalid key #%d", i)
		}
	}
}

func TestValidateKeyset(t *testing.T) {
	var err error
	// nil input
	if err = tink.ValidateKeyset(nil); err == nil {
		t.Errorf("expect an error when keyset is nil")
	}
	// empty keyset
	emptyKeys := make([]*tinkpb.Keyset_Key, 0)
	if err = tink.ValidateKeyset(tink.NewKeyset(1, emptyKeys)); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	// no primary key
	keys := []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
	}
	if err = tink.ValidateKeyset(tink.NewKeyset(2, keys)); err == nil {
		t.Errorf("expect an error when there is no primary key")
	}
	// primary key is disabled
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(2, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = tink.ValidateKeyset(tink.NewKeyset(2, keys)); err == nil {
		t.Errorf("expect an error when primary key is disabled")
	}
	// multiple primary keys
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = tink.ValidateKeyset(tink.NewKeyset(1, keys)); err == nil {
		t.Errorf("expect an error when there are multiple primary keys")
	}
	// invalid keys
	invalidKeys := generateInvalidKeys()
	for i, key := range invalidKeys {
		err = tink.ValidateKeyset(tink.NewKeyset(1, []*tinkpb.Keyset_Key{key}))
		if err == nil {
			t.Errorf("expect an error when validate invalid key %d", i)
		}
	}
}

func generateInvalidKeys() []*tinkpb.Keyset_Key {
	return []*tinkpb.Keyset_Key{
		nil,
		// nil KeyData
		tink.NewKey(nil, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		// unknown status
		tink.NewKey(new(tinkpb.KeyData), tinkpb.KeyStatusType_UNKNOWN_STATUS, 1, tinkpb.OutputPrefixType_TINK),
		// unknown prefix
		tink.NewKey(new(tinkpb.KeyData), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_UNKNOWN_PREFIX),
	}
}

func compareKeyInfo(info *tinkpb.KeysetInfo_KeyInfo, key *tinkpb.Keyset_Key) bool {
	if info.TypeUrl != key.KeyData.TypeUrl ||
		info.Status != key.Status ||
		info.KeyId != key.KeyId ||
		info.OutputPrefixType != key.OutputPrefixType {
		return false
	}
	return true
}
