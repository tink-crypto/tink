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

	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeysethandle"
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
	keyData := tink.CreateKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	keyset := tink.CreateKeyset(1, []*tinkpb.Keyset_Key{key})
	keysetInfo, _ := tink.GetKeysetInfo(keyset)
	h, _ := testkeysethandle.KeysetHandle(keyset)
	// test Keyset
	if h.Keyset() != keyset {
		t.Errorf("Keyset is incorrect")
	}
	// test String()
	if h.String() != keysetInfo.String() {
		t.Errorf("String() returns incorrect value")
	}
}
