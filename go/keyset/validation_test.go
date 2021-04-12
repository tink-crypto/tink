// Copyright 2019 Google LLC
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

package keyset_test

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestValidateKeyVersion(t *testing.T) {
	if keyset.ValidateKeyVersion(2, 1) == nil ||
		keyset.ValidateKeyVersion(1, 1) != nil ||
		keyset.ValidateKeyVersion(1, 2) != nil {
		t.Errorf("incorrect version validation")
	}
}

func TestValidate(t *testing.T) {
	var err error
	// nil input
	if err = keyset.Validate(nil); err == nil {
		t.Errorf("expect an error when keyset is nil")
	}
	// empty keyset
	var emptyKeys []*tinkpb.Keyset_Key
	if err = keyset.Validate(testutil.NewKeyset(1, emptyKeys)); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	// no primary key
	keys := []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
	}
	if err = keyset.Validate(testutil.NewKeyset(2, keys)); err == nil {
		t.Errorf("expect an error when there is no primary key")
	}
	// primary key is disabled
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(2, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = keyset.Validate(testutil.NewKeyset(2, keys)); err == nil {
		t.Errorf("expect an error when primary key is disabled")
	}
	// multiple primary keys
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = keyset.Validate(testutil.NewKeyset(1, keys)); err == nil {
		t.Errorf("expect an error when there are multiple primary keys")
	}
	// invalid keys
	invalidKeys := generateInvalidKeys()
	for i, key := range invalidKeys {
		err = keyset.Validate(testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key}))
		if err == nil {
			t.Errorf("expect an error when validate invalid key %d", i)
		}
	}
	//no primary keys
	keys = []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(1, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_LEGACY),
	}
	if err = keyset.Validate(testutil.NewKeyset(1, keys)); err == nil {
		t.Errorf("expect an error when there are no primary keys")
	}
	// public key only
	keys = []*tinkpb.Keyset_Key{
		testutil.NewKey(testutil.NewKeyData(testutil.EciesAeadHkdfPublicKeyTypeURL, random.GetRandomBytes(10), tinkpb.KeyData_ASYMMETRIC_PUBLIC), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
	}
	if err = keyset.Validate(testutil.NewKeyset(1, keys)); err != nil {
		t.Errorf("valid test failed when using public key only: %v", err)
	}
	// private key
	keys = []*tinkpb.Keyset_Key{
		testutil.NewKey(testutil.NewKeyData(testutil.EciesAeadHkdfPublicKeyTypeURL, random.GetRandomBytes(10), tinkpb.KeyData_ASYMMETRIC_PUBLIC), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		testutil.NewKey(testutil.NewKeyData(testutil.EciesAeadHkdfPrivateKeyTypeURL, random.GetRandomBytes(10), tinkpb.KeyData_ASYMMETRIC_PRIVATE), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
	}
	if err = keyset.Validate(testutil.NewKeyset(1, keys)); err == nil {
		t.Errorf("expect an error when there are keydata other than public")
	}
}

func generateInvalidKeys() []*tinkpb.Keyset_Key {
	return []*tinkpb.Keyset_Key{
		nil,
		// nil KeyData
		testutil.NewKey(nil, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		// unknown status
		testutil.NewKey(new(tinkpb.KeyData), tinkpb.KeyStatusType_UNKNOWN_STATUS, 1, tinkpb.OutputPrefixType_TINK),
		// unknown prefix
		testutil.NewKey(new(tinkpb.KeyData), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_UNKNOWN_PREFIX),
	}
}
