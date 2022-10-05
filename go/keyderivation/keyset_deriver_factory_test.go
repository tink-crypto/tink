// Copyright 2022 Google LLC
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

package keyderivation

import (
	"strings"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// invalidDeriver returns two keys, but wrappedKeysetDeriver accepts only one.
type invalidDeriver struct{}

var _ KeysetDeriver = (*invalidDeriver)(nil)

func (i *invalidDeriver) DeriveKeyset(salt []byte) (*keyset.Handle, error) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	manager := keyset.NewManagerFromHandle(kh)
	if _, err := manager.Add(aead.AES128GCMKeyTemplate()); err != nil {
		return nil, err
	}
	return kh, nil
}

func TestInvalidKeysetDeriverImplementationFails(t *testing.T) {
	entry := &primitiveset.Entry{
		KeyID:     119,
		Primitive: &invalidDeriver{},
		Prefix:    cryptofmt.RawPrefix,
		Status:    tinkpb.KeyStatusType_ENABLED,
		TypeURL:   "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey",
	}
	ps := &primitiveset.PrimitiveSet{
		Primary: entry,
		Entries: map[string][]*primitiveset.Entry{
			cryptofmt.RawPrefix: []*primitiveset.Entry{entry},
		},
	}
	wkd, err := newWrappedKeysetDeriver(ps)
	if err != nil {
		t.Fatalf("newWrappedKeysetDeriver() err = %v, want nil", err)
	}
	if _, err := wkd.DeriveKeyset([]byte("salt")); err == nil {
		t.Error("DeriveKeyset() err = nil, want non-nil")
	} else if !strings.Contains(err.Error(), "exactly one key") {
		t.Errorf("DeriveKeyset() err = %q, doesn't contain %q", err, "exactly one key")
	}
}
