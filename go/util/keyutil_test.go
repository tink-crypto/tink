// Copyright 2017 Google Inc.
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

package util_test

import (
	"github.com/google/tink/go/util/testutil"
	"github.com/google/tink/go/util/util"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"testing"
)

func TestValidateVersion(t *testing.T) {
	if util.ValidateVersion(2, 1) == nil ||
		util.ValidateVersion(1, 1) != nil ||
		util.ValidateVersion(1, 2) != nil {
		t.Errorf("incorrect version validation")
	}
}

func TestGetKeyInfo(t *testing.T) {
	_, err := util.GetKeyInfo(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
	keyData := util.NewKeyData("some url", []byte{1}, tinkpb.KeyData_SYMMETRIC)
	key := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	info, err := util.GetKeyInfo(key)
	if err != nil {
		t.Errorf("unexpected error")
	}
	if !compareKeyInfo(info, key) {
		t.Errorf("KeyInfo mismatched")
	}
}

func TestGetKeysetInfo(t *testing.T) {
	_, err := util.GetKeysetInfo(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
	keyData := util.NewKeyData("some url", []byte{1}, tinkpb.KeyData_SYMMETRIC)
	key := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := util.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	keysetInfo, err := util.GetKeysetInfo(keyset)
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
		if err := util.ValidateKey(key); err == nil {
			t.Errorf("expect an error for invalid key #%d", i)
		}
	}
}

func TestValidateKeyset(t *testing.T) {
	var err error
	// nil input
	if err = util.ValidateKeyset(nil); err == nil {
		t.Errorf("expect an error when keyset is nil")
	}
	// empty keyset
	emptyKeys := make([]*tinkpb.Keyset_Key, 0)
	if err = util.ValidateKeyset(util.NewKeyset(1, emptyKeys)); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	// no primary key
	var keys []*tinkpb.Keyset_Key
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
	}
	if err = util.ValidateKeyset(util.NewKeyset(2, keys)); err == nil {
		t.Errorf("expect an error when there is no primary key")
	}
	// primary key is disabled
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(2, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = util.ValidateKeyset(util.NewKeyset(2, keys)); err == nil {
		t.Errorf("expect an error when primary key is disabled")
	}
	// multiple primary keys
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = util.ValidateKeyset(util.NewKeyset(1, keys)); err == nil {
		t.Errorf("expect an error when there are multiple primary keys")
	}
	// invalid keys
	invalidKeys := generateInvalidKeys()
	for i, key := range invalidKeys {
		err = util.ValidateKeyset(util.NewKeyset(1, []*tinkpb.Keyset_Key{key}))
		if err == nil {
			t.Errorf("expect an error when validate invalid key %d", i)
		}
	}
}

func generateInvalidKeys() []*tinkpb.Keyset_Key {
	return []*tinkpb.Keyset_Key{
		nil,
		// nil KeyData
		util.NewKey(nil, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		// unknown status
		util.NewKey(new(tinkpb.KeyData), tinkpb.KeyStatusType_UNKNOWN_STATUS, 1, tinkpb.OutputPrefixType_TINK),
		// unknown prefix
		util.NewKey(new(tinkpb.KeyData), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_UNKNOWN_PREFIX),
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
