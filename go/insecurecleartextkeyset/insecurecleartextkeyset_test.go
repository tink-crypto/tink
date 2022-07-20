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

package insecurecleartextkeyset_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testutil"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestInvalidInput(t *testing.T) {
	if _, err := insecurecleartextkeyset.Read(nil); err == nil {
		t.Error("insecurecleartextkeyset.Read should not accept nil as keyset")
	}
	if err := insecurecleartextkeyset.Write(nil, &keyset.MemReaderWriter{}); err == nil {
		t.Error("insecurecleartextkeyset.Write should not accept nil as keyset")
	}
	if err := insecurecleartextkeyset.Write(&keyset.Handle{}, nil); err == nil {
		t.Error("insecurecleartextkeyset.Write should not accept nil as writer")
	}
}

func TestHandleFromReader(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	manager := testutil.NewHMACKeysetManager()
	handle, err := manager.Handle()
	if handle == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}
	ks := insecurecleartextkeyset.KeysetMaterial(handle)
	parsedHandle, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		t.Fatalf("unexpected error reading keyset: %v", err)
	}
	parsedKs := insecurecleartextkeyset.KeysetMaterial(parsedHandle)
	if !proto.Equal(ks, parsedKs) {
		t.Errorf("parsed keyset (%s) doesn't match original keyset (%s)", parsedKs, ks)
	}
}

func TestWrite(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	h, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		t.Fatalf("unexpected error creating new KeysetHandle: %v", err)
	}
	exported := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(h, exported); err != nil {
		t.Fatalf("unexpected error writing keyset: %v", err)
	}
	if !proto.Equal(exported.Keyset, ks) {
		t.Errorf("exported keyset (%s) doesn't match original keyset (%s)", exported.Keyset, ks)
	}
}
