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
	"github.com/google/tink/go/testkeyset"

	"github.com/google/tink/go/mac"
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

func TestUnknowOutputPrefixTypeFails(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kt.OutputPrefixType = tinkpb.OutputPrefixType_UNKNOWN_PREFIX
	err := ksm1.Rotate(kt)
	if err == nil {
		t.Errorf("ksm1.Rotate(kt) where kt has an unknown prefix succeeded, want error")
	}
}
