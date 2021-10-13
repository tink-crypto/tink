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
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeysetManagerBasic(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	err := ksm.Rotate(kt)
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}
	h, err := ksm.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks := testkeyset.KeysetMaterial(h)
	if len(ks.Key) != 1 {
		t.Errorf("expect the number of keys in the keyset is 1")
		t.FailNow()
	}
	if ks.Key[0].KeyId != ks.PrimaryKeyId ||
		ks.Key[0].KeyData.TypeUrl != testutil.HMACTypeURL ||
		ks.Key[0].Status != tinkpb.KeyStatusType_ENABLED ||
		ks.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("incorrect key information: %s", ks.Key[0])
	}
}

func TestExistingKeyset(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	err := ksm1.Rotate(kt)
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}

	h1, err := ksm1.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks1 := testkeyset.KeysetMaterial(h1)

	ksm2 := keyset.NewManagerFromHandle(h1)
	ksm2.Rotate(kt)
	h2, err := ksm2.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)

	if len(ks2.Key) != 2 {
		t.Errorf("expect the number of keys to be 2, got %d", len(ks2.Key))
	}
	if ks1.Key[0].String() != ks2.Key[0].String() {
		t.Errorf("expect the first key in two keysets to be the same")
	}
	if ks2.Key[1].KeyId != ks2.PrimaryKeyId {
		t.Errorf("expect the second key to be primary")
	}
}

func TestKeysetManagerFull(t *testing.T) {
	// test a full keyset manager cycle: add, get info, set primary
	ksm := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	_, err := ksm.Add(kt)
	if err != nil {
		t.Errorf("expected no error but got %s", err)
	}
	h1, _ := ksm.Handle()
	info := h1.KeysetInfo()
	if len(info.KeyInfo) != 1 {
		t.Errorf("expected one key but got %d", len(info.KeyInfo))
		t.Fail()
	}
	newPrimaryKey := info.KeyInfo[0].KeyId
	err = ksm.SetPrimary(newPrimaryKey)
	if err != nil {
		t.Errorf("expected no error but got %s", err)
	}
	// validate this is a valid keyset
	ks1 := testkeyset.KeysetMaterial(h1)
	err = keyset.Validate(ks1)
	if err != nil {
		t.Errorf("expected no error but got %s", err)
	}
}

func TestUnknowOutputPrefixTypeFails(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kt.OutputPrefixType = tinkpb.OutputPrefixType_UNKNOWN_PREFIX
	err := ksm1.Rotate(kt)
	if err == nil {
		t.Errorf("ksm1.Rotate(kt) where kt has an unknown prefix succeeded, want error")
	}
}

func TestKeysetManagerWithNilKeysetTemplate(t *testing.T) {
	// ops with nil template should fail
	ksm1 := keyset.NewManager()
	err := ksm1.Rotate(nil)
	if err == nil {
		t.Errorf("ksm1.Rotate succeeded, but want error")
	}
	_, err = ksm1.Add(nil)
	if err == nil {
		t.Errorf("ksm1.Add succeeded, but want error")
	}
}

func TestKeysetManagerAdd(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	keyID, err := ksm1.Add(kt)
	if err != nil {
		t.Errorf("expected no error but got %s", err)
	}
	h, err := ksm1.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks := testkeyset.KeysetMaterial(h)
	if len(ks.Key) != 1 {
		t.Errorf("expected one key but got %d", len(ks.Key))
		t.Fail()
	}
	if ks.Key[0].KeyId != keyID {
		t.Errorf("expected added keyID to be %d but got %d", keyID, ks.Key[0].KeyId)
	}
	if ks.Key[0].Status != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("expected key to be enabled but got %s", ks.Key[0].Status.String())
	}
	// no primary key set
	if ks.PrimaryKeyId != 0 {
		t.Errorf("expected no primary key but got %d", ks.PrimaryKeyId)
	}
}

func TestKeysetManagerAddWithBadTemplate(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := &tinkpb.KeyTemplate{
		TypeUrl:          "invalid type",
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
	_, err := ksm1.Add(kt)
	if err == nil {
		t.Errorf("ksm1.Add succeeded, want error")
	}
}

func TestKeysetManagerEnable(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_DISABLED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err := ksm1.Enable(keyID)
	if err != nil {
		t.Errorf("expected no error but got error %s", err)
	}
	h2, _ := ksm1.Handle()
	ks2 := testkeyset.KeysetMaterial(h2)
	if len(ks2.Key) != 1 {
		t.Errorf("expect only one key, got %d", len(ks2.Key))
		t.FailNow()
	}
	if ks2.Key[0].KeyId != keyID {
		t.Errorf("expected keyID %d, got %d", keyID, ks2.Key[0].KeyId)
	}
	if ks2.Key[0].Status != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("expected key to be enabled, but got %s", ks2.Key[0].Status.String())
	}
}

func TestKeysetManagerEnableWithUnknownStatus(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_UNKNOWN_STATUS, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err := ksm1.Enable(keyID)
	if err == nil {
		t.Errorf("ksm1.Enable where key has unknown status succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot enable") {
		t.Errorf("expected 'cannot enable' message, got %s", err)
	}
}

func TestKeysetManagerEnableWithDestroyed(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", nil, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_DESTROYED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err := ksm1.Enable(keyID)
	if err == nil {
		t.Errorf("ksm1.Enable where key was destroyed succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot enable") {
		t.Errorf("expected 'cannot enable' message, got %s", err)
	}
}

func TestKeysetManagerEnableWithMissingKey(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_UNKNOWN_STATUS, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err := ksm1.Enable(uint32(43))
	if err == nil {
		t.Errorf("ksm1.Enable where key doesn't exist succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimary(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err := ksm1.SetPrimary(newKeyID)
	if err != nil {
		t.Errorf("expected no error but got error %s", err)
	}
	h2, _ := ksm1.Handle()
	ks2 := testkeyset.KeysetMaterial(h2)
	if len(ks2.Key) != 2 {
		t.Errorf("expected two keys, got %d", len(ks2.Key))
	}
	if ks2.PrimaryKeyId != newKeyID {
		t.Errorf("expected new key to be primary, got %d", ks2.PrimaryKeyId)
	}
}

func TestKeysetManagerSetPrimaryWithDisabledKey(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	// create a disabled key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DISABLED, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err := ksm1.SetPrimary(newKeyID)
	if err == nil {
		t.Errorf("ksm1.SetPrimary on disabled key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimaryWithDestroyedKey(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	// create a destroyed key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DESTROYED, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err := ksm1.SetPrimary(newKeyID)
	if err == nil {
		t.Errorf("ksm1.SetPrimary on destroyed key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimaryWithUnknownStatusKey(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	// create an unknown status key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_UNKNOWN_STATUS, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err := ksm1.SetPrimary(newKeyID)
	if err == nil {
		t.Errorf("ksm1.SetPrimary on unknown key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimaryWithMissingKey(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	// create an unknown status key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_UNKNOWN_STATUS, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err := ksm1.SetPrimary(uint32(44))
	if err == nil {
		t.Errorf("ksm1.SetPrimary on missing key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' message, got %s", err)
	}
}

func TestKeysetManagerDisable(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err := ksm1.Disable(otherKeyID)
	if err != nil {
		t.Errorf("expected no error but got error %s", err)
	}
	h2, _ := ksm1.Handle()
	ks2 := testkeyset.KeysetMaterial(h2)
	if ks2.PrimaryKeyId != primaryKeyID {
		t.Errorf("expected same key to be primary, got %d", ks2.PrimaryKeyId)
	}
	if len(ks2.Key) != 2 {
		t.Errorf("expected two keys, got %d", len(ks2.Key))
		t.FailNow()
	}
	if ks2.Key[1].Status != tinkpb.KeyStatusType_DISABLED {
		t.Errorf("expected key to be disabled, got %s", ks2.Key[1].Status.String())
	}
}

func TestKeysetManagerDisableWithPrimaryKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err := ksm1.Disable(primaryKeyID)
	if err == nil {
		t.Errorf("ksm1.Disable on primary key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot disable the primary key") {
		t.Errorf("expected 'cannot disable the primary key' message, got %s", err)
	}
	h2, _ := ksm1.Handle()
	ks2 := testkeyset.KeysetMaterial(h2)
	if ks2.PrimaryKeyId != primaryKeyID {
		t.Errorf("expected same key to be primary, got %d", ks2.PrimaryKeyId)
	}
}

func TestKeysetManagerDisableWithDestroyedKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	// destroyed key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DESTROYED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err := ksm1.Disable(otherKeyID)
	if err == nil {
		t.Errorf("ksm1.Disable on destroyed key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot disable") {
		t.Errorf("expected 'cannot disable' message, got %s", err)
	}
}

func TestKeysetManagerDisableWithMissingKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err := ksm1.Disable(uint32(44))
	if err == nil {
		t.Errorf("ksm1.Disable on missing key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' message, got %s", err)
	}
}

func TestKeysetManagerDestroy(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// destroy key
	err := ksm1.Destroy(otherKeyID)
	if err != nil {
		t.Errorf("expected no error but got error %s", err)
	}
	h2, _ := ksm1.Handle()
	ks2 := testkeyset.KeysetMaterial(h2)
	if ks2.PrimaryKeyId != primaryKeyID {
		t.Errorf("unexpected primary key ID, got %d", ks2.PrimaryKeyId)
	}
	if len(ks2.Key) != 2 {
		t.Errorf("expected two keys got %d", len(ks2.Key))
		t.FailNow()
	}
	if ks2.Key[0].Status != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("unexpected status got %s", ks2.Key[0].Status)
	}
	if ks2.Key[0].KeyId != primaryKeyID {
		t.Errorf("unexpected key ID, got %d", ks2.Key[0].KeyId)
	}
	if ks2.Key[1].KeyId != otherKeyID {
		t.Errorf("unexpected other key ID, got %d", ks2.Key[1].KeyId)
	}
	if ks2.Key[1].Status != tinkpb.KeyStatusType_DESTROYED {
		t.Errorf("unexpected status got %s", ks2.Key[1].Status.String())
	}
	if ks2.Key[1].KeyData == nil {
		t.Errorf("expected key data not to be nil")
		t.FailNow()
	}
	if ks2.Key[1].KeyData.Value != nil {
		t.Errorf("expected key data value to be nil, got not nil")
	}
	if ks2.Key[1].KeyData.TypeUrl != "" {
		t.Errorf("expected empty type url, got %s", ks2.Key[1].KeyData.TypeUrl)
	}
	if ks2.Key[1].KeyData.KeyMaterialType != tinkpb.KeyData_UNKNOWN_KEYMATERIAL {
		t.Errorf("unexpected key material type, got %s", ks2.Key[1].KeyData.KeyMaterialType.String())
	}
}

func TestKeysetManagerDestroyWithKeysetInfo(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// destroy key
	err := ksm1.Destroy(otherKeyID)
	if err != nil {
		t.Errorf("expected no error but got error %s", err)
	}
	// verify keyset info is not nil
	info := h1.KeysetInfo()
	if info == nil {
		t.Errorf("expected keyset info to be not nil, got nil")
	}
}

func TestKeysetManagerDestroyWithPrimaryKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// destroy key
	err := ksm1.Destroy(primaryKeyID)
	if err == nil {
		t.Errorf("ksm1.Destroy on primary key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot destroy the primary key") {
		t.Errorf("expected 'cannot destroy the primary key' message got %s", err)
	}
}

func TestKeysetManagerDestroyWithUnknownStatus(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_UNKNOWN_STATUS, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// destroy key
	err := ksm1.Destroy(otherKeyID)
	if err == nil {
		t.Errorf("ksm1.Destroy on key with unknown status succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot destroy") {
		t.Errorf("expected 'cannot destroy' message got %s", err)
	}
}

func TestKeysetManagerDestroyWithMissingKey(t *testing.T) {
	primaryKeyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// destroy key
	err := ksm1.Destroy(uint32(43))
	if err == nil {
		t.Errorf("ksm1.Destroy on key with unknown status succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' message got %s", err)
	}
}

func TestKeysetManagerDelete(t *testing.T) {
	keyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// delete key
	err := ksm1.Delete(otherKeyID)
	if err != nil {
		t.Errorf("expected no error but got error %s", err)
	}
	h2, _ := ksm1.Handle()
	ks2 := testkeyset.KeysetMaterial(h2)
	if len(ks2.Key) != 1 {
		t.Errorf("expected only one key but got %d", len(ks2.Key))
		t.Fail()
	}
	if ks2.Key[0].KeyId != ks2.PrimaryKeyId || ks2.Key[0].KeyId != keyID {
		t.Errorf("expected keyID %d to be present but got %d", keyID, ks2.Key[0].KeyId)
	}
	if ks2.Key[0].Status != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("expected key to be enabled but got %s", ks2.Key[0].Status.String())
	}
}

func TestKeysetManagerDeleteWithPrimaryKey(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// delete key
	err := ksm1.Delete(keyID)
	if err == nil {
		t.Errorf("ksm1.Delete succeeded but expected error")
	}
	if !strings.Contains(err.Error(), "primary key") {
		t.Errorf("expected 'primary key' message but got %s", err)
	}
}

func TestKeysetManagerDeleteWithMissingKey(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, _ := testkeyset.NewHandle(ks1)
	ksm1 := keyset.NewManagerFromHandle(h1)
	// delete key
	err := ksm1.Delete(uint32(43))
	if err == nil {
		t.Errorf("ksm1.Delete succeeded but expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' message but got %s", err)
	}
}

func TestKeysetManagerWithEmptyManager(t *testing.T) {
	// all ops with empty manager should fail
	ksm1 := &keyset.Manager{}
	_, err := ksm1.Add(mac.HMACSHA256Tag128KeyTemplate())
	if err == nil {
		t.Errorf("ksm1.Add succeeded on empty manager, want error")
	}
	err = ksm1.Rotate(mac.HMACSHA256Tag128KeyTemplate())
	if err == nil {
		t.Errorf("ksm1.Rotate succeeded on empty manager, want error")
	}
	err = ksm1.SetPrimary(0)
	if err == nil {
		t.Errorf("ksm1.SetPrimary succeeded on empty manager, want error")
	}
	err = ksm1.Destroy(0)
	if err == nil {
		t.Errorf("ksm1.Destroy succeeded on empty manager, want error")
	}
	err = ksm1.Enable(0)
	if err == nil {
		t.Errorf("ksm1.Enable succeeded on empty manager, want error")
	}
	err = ksm1.Delete(0)
	if err == nil {
		t.Errorf("ksm1.Delete succeeded on empty manager, want error")
	}
	err = ksm1.Disable(0)
	if err == nil {
		t.Errorf("ksm1.Disable succeeded on empty manager, want error")
	}
}
