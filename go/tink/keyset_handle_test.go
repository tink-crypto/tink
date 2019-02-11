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
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/testkeysethandle"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestNewKeysetHandle(t *testing.T) {
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kh, err := tink.NewKeysetHandle(kt)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	keyset := kh.Keyset()
	if len(keyset.Key) != 1 {
		t.Errorf("incorrect number of keys in the keyset: %d", len(keyset.Key))
	}
	key := keyset.Key[0]
	if keyset.PrimaryKeyId != key.KeyId {
		t.Errorf("incorrect primary key id, expect %d, got %d", key.KeyId, keyset.PrimaryKeyId)
	}
	if key.KeyData.TypeUrl != kt.TypeUrl {
		t.Errorf("incorrect type url, expect %s, got %s", kt.TypeUrl, key.KeyData.TypeUrl)
	}
	if _, err = mac.New(kh); err != nil {
		t.Errorf("cannot get primitive from generated keyset handle: %s", err)
	}
}

func TestNewKeysetHandleWithInvalidInput(t *testing.T) {
	// template unregistered TypeUrl
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.TypeUrl = "some unknown TypeUrl"
	if _, err := tink.NewKeysetHandle(template); err == nil {
		t.Errorf("expect an error when TypeUrl is not registered")
	}
	// nil
	if _, err := tink.NewKeysetHandle(nil); err == nil {
		t.Errorf("expect an error when template is nil")
	}
}

func TestFromKeyset(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeysethandle.KeysetHandle(keyset)
	// test Keyset
	if h.Keyset() != keyset {
		t.Errorf("Keyset is incorrect")
	}
}

func TestNewKeysetHandleFromReader(t *testing.T) {
	masterKey, err := aead.NewAESGCM([]byte(strings.Repeat("A", 32)))
	if err != nil {
		t.Errorf("aead.NewAESGCM(): %v", err)
	}

	// Create a keyset
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeysethandle.KeysetHandle(keyset)

	memKeyset := &tink.MemKeyset{}
	if err := h.Write(memKeyset, masterKey); err != nil {
		t.Fatalf("handle.Write(): %v", err)
	}
	h2, err := tink.NewKeysetHandleFromReader(memKeyset, masterKey)
	if err != nil {
		t.Fatalf("NewKeysetHandleFromReader(): %v", err)
	}
	if !proto.Equal(h.Keyset(), h2.Keyset()) {
		t.Fatalf("Decrypt failed: got %v, want %v", h2, h)
	}
}

func TestNewKeysetHandleFromReaderWithNoSecrets(t *testing.T) {
	// Create a keyset containing public key material
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeysethandle.KeysetHandle(keyset)

	memKeyset := &tink.MemKeyset{}
	if err := h.WriteWithNoSecrets(memKeyset); err != nil {
		t.Fatalf("handle.WriteWithNoSecrets(): %v", err)
	}
	h2, err := tink.NewKeysetHandleFromReaderWithNoSecrets(memKeyset)
	if err != nil {
		t.Fatalf("NewKeysetHandleFromReaderWithNoSecrets(): %v", err)
	}
	if !proto.Equal(h.Keyset(), h2.Keyset()) {
		t.Fatalf("Decrypt failed: got %v, want %v", h2, h)
	}
}

func TestWithNoSecretsFunctionsFailWhenHandlingSecretKeyMaterial(t *testing.T) {
	// Create a keyset containing secret key material (symmetric)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, _ := testkeysethandle.KeysetHandle(keyset)

	if err := h.WriteWithNoSecrets(&tink.MemKeyset{}); err == nil {
		t.Error("handle.WriteWithNoSecrets() should fail when exporting secret key material")
	}

	if _, err := tink.NewKeysetHandleFromReaderWithNoSecrets(&tink.MemKeyset{Keyset: h.Keyset()}); err == nil {
		t.Error("NewKeysetHandleFromReaderWithNoSecrets should fail when importing secret key material")
	}
}
