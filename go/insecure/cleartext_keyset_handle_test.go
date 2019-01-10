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

package insecure_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/insecure"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestFromKeyset(t *testing.T) {
	keyData := tink.CreateKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := tink.CreateKeyset(1, []*tinkpb.Keyset_Key{key})
	keysetInfo, _ := tink.GetKeysetInfo(keyset)
	h, err := insecure.KeysetHandle(keyset)
	if err != nil {
		t.Errorf("unexpected error when creating new KeysetHandle")
	}
	// test Keyset
	if h.Keyset() != keyset {
		t.Errorf("Keyset is incorrect")
	}
	// test String()
	if h.String() != keysetInfo.String() {
		t.Errorf("String() returns incorrect value")
	}
}

func TestFromKeysetWithInvalidInput(t *testing.T) {
	if _, err := insecure.KeysetHandle(nil); err == nil {
		t.Errorf("FromKeyset should not accept nil as Keyset")
	}
}

func TestKeysetHandleFromSerializedProto(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	manager := testutil.NewHMACKeysetManager()
	handle, err := manager.KeysetHandle()
	if handle == nil || err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	serializedKeyset, err := proto.Marshal(handle.Keyset())
	if err != nil {
		t.Errorf("cannot serialize keyset: %s", err)
	}
	// create handle from serialized keyset
	parsedHandle, err := insecure.KeysetHandleFromSerializedProto(serializedKeyset)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if handle.Keyset().String() != parsedHandle.Keyset().String() {
		t.Errorf("parsed keyset doesn't match the original")
	}
	// create handle from keyset
	parsedHandle, err = insecure.KeysetHandle(handle.Keyset())
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if handle.Keyset().String() != parsedHandle.Keyset().String() {
		t.Errorf("parsed keyset doesn't match the original")
	}
}

func TestKeysetHandleFromSerializedProtoWithInvalidInput(t *testing.T) {
	manager := testutil.NewHMACKeysetManager()
	handle, err := manager.KeysetHandle()
	if handle == nil || err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	serializedKeyset, err := proto.Marshal(handle.Keyset())
	if err != nil {
		t.Errorf("cannot serialize keyset: %s", err)
	}
	serializedKeyset[0] = 0
	_, err = insecure.KeysetHandleFromSerializedProto(serializedKeyset)
	if err == nil {
		t.Errorf("expect an error when input is an invalid serialized keyset")
	}
	_, err = insecure.KeysetHandleFromSerializedProto([]byte{})
	if err == nil {
		t.Errorf("expect an error when input is an empty slice")
	}
	_, err = insecure.KeysetHandleFromSerializedProto(nil)
	if err == nil {
		t.Errorf("expect an error when input is nil")
	}
}
