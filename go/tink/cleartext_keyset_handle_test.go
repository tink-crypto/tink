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
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
)

func setupCleartextKeysetHandleTest() {
	if _, err := mac.RegisterStandardKeyTypes(); err != nil {
		panic(fmt.Sprintf("cannot register mac key types: %s", err))
	}
}

func TestCleartextKeysetHandleParseBasic(t *testing.T) {
	setupCleartextKeysetHandleTest()

	// Create a keyset that contains a single HmacKey.
	manager := testutil.NewHmacKeysetManager()
	handle, err := manager.GetKeysetHandle()
	if handle == nil || err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	serializedKeyset, err := proto.Marshal(handle.Keyset())
	if err != nil {
		t.Errorf("cannot serialize keyset: %s", err)
	}
	// create handle rom serialized keyset
	parsedHandle, err := tink.CleartextKeysetHandle().ParseSerializedKeyset(serializedKeyset)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if handle.Keyset().String() != parsedHandle.Keyset().String() {
		t.Errorf("parsed keyset doesn't match the original")
	}
	// create handle from keyset
	parsedHandle, err = tink.CleartextKeysetHandle().ParseKeyset(handle.Keyset())
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if handle.Keyset().String() != parsedHandle.Keyset().String() {
		t.Errorf("parsed keyset doesn't match the original")
	}
}

func TestCleartextKeysetHandleParseWithInvalidInput(t *testing.T) {
	setupCleartextKeysetHandleTest()

	manager := testutil.NewHmacKeysetManager()
	handle, err := manager.GetKeysetHandle()
	if handle == nil || err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	serializedKeyset, err := proto.Marshal(handle.Keyset())
	if err != nil {
		t.Errorf("cannot serialize keyset: %s", err)
	}
	serializedKeyset[0] = 0
	_, err = tink.CleartextKeysetHandle().ParseSerializedKeyset(serializedKeyset)
	if err == nil {
		t.Errorf("expect an error when input is an invalid serialized keyset")
	}
	_, err = tink.CleartextKeysetHandle().ParseSerializedKeyset([]byte{})
	if err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
	_, err = tink.CleartextKeysetHandle().ParseSerializedKeyset(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
	_, err = tink.CleartextKeysetHandle().ParseKeyset(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
}

func TestCleartextKeysetHandleGenerateNewBasic(t *testing.T) {
	setupCleartextKeysetHandleTest()

	macTemplate := mac.HmacSha256Tag128KeyTemplate()
	handle, err := tink.CleartextKeysetHandle().GenerateNew(macTemplate)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	keyset := handle.Keyset()
	if len(keyset.Key) != 1 {
		t.Errorf("incorrect number of keys in the keyset: %d", len(keyset.Key))
	}
	key := keyset.Key[0]
	if keyset.PrimaryKeyId != key.KeyId {
		t.Errorf("incorrect primary key id, expect %d, got %d", key.KeyId, keyset.PrimaryKeyId)
	}
	if key.KeyData.TypeUrl != macTemplate.TypeUrl {
		t.Errorf("incorrect type url, expect %s, got %s", macTemplate.TypeUrl, key.KeyData.TypeUrl)
	}
	if _, err = mac.GetPrimitive(handle); err != nil {
		t.Errorf("cannot get primitive from generated keyset handle: %s", err)
	}
}

func TestCleartextKeysetHandleGenerateNewWithInvalidInput(t *testing.T) {
	setupCleartextKeysetHandleTest()

	// template unregistered TypeUrl
	template := mac.HmacSha256Tag128KeyTemplate()
	template.TypeUrl = "some unknown TypeUrl"
	if _, err := tink.CleartextKeysetHandle().GenerateNew(template); err == nil {
		t.Errorf("expect an error when TypeUrl is not registered")
	}
	// nil
	if _, err := tink.CleartextKeysetHandle().GenerateNew(nil); err == nil {
		t.Errorf("expect an error when template is nil")
	}
}
