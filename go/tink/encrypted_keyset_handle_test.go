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

package tink_test

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead/aead"
	"github.com/google/tink/go/mac/mac"
	"github.com/google/tink/go/tink/tink"
	"github.com/google/tink/go/util/testutil"
	"github.com/google/tink/go/util/util"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"testing"
)

func setupEncryptedKeysetHandleTest() {
	if _, err := aead.Config().RegisterStandardKeyTypes(); err != nil {
		panic(fmt.Sprintln("cannot register aead key types: %s", err))
	}
	if _, err := mac.Config().RegisterStandardKeyTypes(); err != nil {
		panic(fmt.Sprintln("cannot register mac key types: %s", err))
	}
}

func TestEncryptedKeysetHandleInstance(t *testing.T) {
	if handle := tink.EncryptedKeysetHandle(); handle == nil {
		t.Errorf("EncryptedKeysetHandle() returns nil")
	}
}

func TestEncryptedKeysetHandleParseBasic(t *testing.T) {
	setupEncryptedKeysetHandleTest()
	masterKey := newMasterKey()
	keyset := testutil.NewTestAesGcmKeyset(tinkpb.OutputPrefixType_TINK)
	encryptedKeyset, _ := tink.EncryptKeyset(keyset, masterKey)

	// ParseKeyset
	handle, err := tink.EncryptedKeysetHandle().ParseKeyset(encryptedKeyset, masterKey)
	if err != nil {
		t.Errorf("unexpected error when parsing keyset: %s", err)
	}
	if err := validateKeysetHandle(handle, keyset, encryptedKeyset); err != nil {
		t.Errorf("%s", err)
	}
	// ParseSerializedKeyset
	serialized, _ := proto.Marshal(encryptedKeyset)
	handle, err = tink.EncryptedKeysetHandle().ParseSerializedKeyset(serialized, masterKey)
	if err != nil {
		t.Errorf("unexpected error when parsing serialized keyset: %s", err)
	}
	if err := validateKeysetHandle(handle, keyset, encryptedKeyset); err != nil {
		t.Errorf("%s", err)
	}
}

func TestEncryptedKeysetHandleParseWithInvalidMasterKey(t *testing.T) {
	setupEncryptedKeysetHandleTest()
	masterKey := newMasterKey()
	keyset := testutil.NewTestAesGcmKeyset(tinkpb.OutputPrefixType_TINK)
	encryptedKeyset, _ := tink.EncryptKeyset(keyset, masterKey)
	serialized, _ := proto.Marshal(encryptedKeyset)

	// wrong master key
	_, err := tink.EncryptedKeysetHandle().ParseKeyset(encryptedKeyset, newMasterKey())
	if err == nil {
		t.Errorf("expect an error when master key is wrong")
	}
	_, err = tink.EncryptedKeysetHandle().ParseSerializedKeyset(serialized, newMasterKey())
	if err == nil {
		t.Errorf("expect an error when master key is wrong")
	}
}

func TestEncryptedKeysetHandleParseWithInvalidKeyset(t *testing.T) {
	setupEncryptedKeysetHandleTest()
	masterKey := newMasterKey()
	keyset := testutil.NewTestAesGcmKeyset(tinkpb.OutputPrefixType_TINK)
	encryptedKeyset, _ := tink.EncryptKeyset(keyset, masterKey)
	serialized, _ := proto.Marshal(encryptedKeyset)

	// modified
	serialized[0] = 0
	_, err := tink.EncryptedKeysetHandle().ParseSerializedKeyset(serialized, masterKey)
	if err == nil {
		t.Errorf("expect an error when serialized keyset is modified")
	}
	// encrypted keyset contains a keyset with no key
	keyset = util.NewKeyset(1, []*tinkpb.Keyset_Key{})
	encryptedKeyset, _ = tink.EncryptKeyset(keyset, masterKey)
	serialized, _ = proto.Marshal(encryptedKeyset)
	_, err = tink.EncryptedKeysetHandle().ParseKeyset(encryptedKeyset, masterKey)
	if err == nil {
		t.Errorf("expect an error when keyset doesn't contain any key")
	}
	_, err = tink.EncryptedKeysetHandle().ParseSerializedKeyset(serialized, masterKey)
	if err == nil {
		t.Errorf("expect an error when keyset doesn't contain any key")
	}
}

func TestEncryptedKeysetHandleParseWithVoidInput(t *testing.T) {
	setupEncryptedKeysetHandleTest()
	masterKey := newMasterKey()
	keyset := testutil.NewTestAesGcmKeyset(tinkpb.OutputPrefixType_TINK)
	encryptedKeyset, _ := tink.EncryptKeyset(keyset, masterKey)
	serialized, _ := proto.Marshal(encryptedKeyset)

	// master key is nil
	_, err := tink.EncryptedKeysetHandle().ParseKeyset(encryptedKeyset, nil)
	if err == nil {
		t.Errorf("expect an error when master key is nil")
	}
	_, err = tink.EncryptedKeysetHandle().ParseSerializedKeyset(serialized, nil)
	if err == nil {
		t.Errorf("expect an error when master key is nil")
	}
	// encrypted keyset is nil
	_, err = tink.EncryptedKeysetHandle().ParseKeyset(nil, masterKey)
	if err == nil {
		t.Errorf("expect an error when keyset is nil")
	}
	_, err = tink.EncryptedKeysetHandle().ParseSerializedKeyset(nil, masterKey)
	if err == nil {
		t.Errorf("expect an error when serialized keyset is nil")
	}
	// encrypted keyset is empty array
	_, err = tink.EncryptedKeysetHandle().ParseSerializedKeyset([]byte{}, masterKey)
	if err == nil {
		t.Errorf("expect an error when keyset is an empty slice")
	}
}

func TestEncryptedKeysetHandleGenerateNewBasic(t *testing.T) {
	setupEncryptedKeysetHandleTest()
	keyTemplate := mac.HmacSha256Tag128KeyTemplate()
	masterKey := newMasterKey()

	handle, err := tink.EncryptedKeysetHandle().GenerateNew(keyTemplate, masterKey)
	if err != nil || handle == nil {
		t.Errorf("generating new handle failed: %s", err)
	}
}

func TestEncryptedKeysetHandleGenerateNewWithVoidInput(t *testing.T) {
	keyTemplate := mac.HmacSha256Tag128KeyTemplate()
	masterKey := newMasterKey()

	// template is nil
	if _, err := tink.EncryptedKeysetHandle().GenerateNew(nil, masterKey); err == nil {
		t.Errorf("expect an error when template is nil")
	}
	// master key is nil
	if _, err := tink.EncryptedKeysetHandle().GenerateNew(keyTemplate, nil); err == nil {
		t.Errorf("expect an error when master key is nil")
	}
}

func validateKeysetHandle(handle *tink.KeysetHandle,
	keyset *tinkpb.Keyset,
	encryptedKeyset *tinkpb.EncryptedKeyset) error {
	if handle.Keyset().String() != keyset.String() {
		return fmt.Errorf("incorrect keyset")
	}
	if handle.EncryptedKeyset().String() != encryptedKeyset.String() {
		return fmt.Errorf("incorrect encrypted keyset")
	}
	return nil
}

func newMasterKey() tink.Aead {
	keyTemplate := aead.Aes128GcmKeyTemplate()
	keyData, _ := tink.Registry().NewKeyData(keyTemplate)
	p, _ := tink.Registry().GetPrimitiveFromKeyData(keyData)
	return p.(tink.Aead)
}
