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

func TestInvalidInput(t *testing.T) {
	if _, err := insecure.NewKeysetHandleFromReader(nil); err == nil {
		t.Error("NewKeysetHandleFromReader should not accept nil as keyset")
	}
	if err := insecure.WriteUnencryptedKeysetHandle(nil, &tink.MemKeyset{}); err == nil {
		t.Error("WriteUnencryptedKeysetHandle should not accept nil as keyset")
	}
	if err := insecure.WriteUnencryptedKeysetHandle(&tink.KeysetHandle{}, nil); err == nil {
		t.Error("WriteUnencryptedKeysetHandle should not accept nil as writer")
	}
}

func TestKeysetHandleFromReader(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	manager := testutil.NewHMACKeysetManager()
	handle, err := manager.KeysetHandle()
	if handle == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}
	parsedHandle, err := insecure.NewKeysetHandleFromReader(&tink.MemKeyset{Keyset: handle.Keyset()})
	if err != nil {
		t.Fatalf("unexpected error reading keyset: %v", err)
	}
	if !proto.Equal(handle.Keyset(), parsedHandle.Keyset()) {
		t.Errorf("parsed keyset (%s) doesn't match original keyset (%s)", parsedHandle.Keyset(), handle.Keyset())
	}
}

func TestWriteUnencryptedKeysetHandle(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, err := insecure.NewKeysetHandleFromReader(&tink.MemKeyset{Keyset: keyset})
	if err != nil {
		t.Fatalf("unexpected error creating new KeysetHandle: %v", err)
	}
	exported := &tink.MemKeyset{}
	if err := insecure.WriteUnencryptedKeysetHandle(h, exported); err != nil {
		t.Fatalf("unexpected error writing keyset: %v", err)
	}
	if !proto.Equal(exported.Keyset, keyset) {
		t.Errorf("exported keyset (%s) doesn't match original keyset (%s)", exported.Keyset, keyset)
	}
}
