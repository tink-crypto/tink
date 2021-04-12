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
	"bytes"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestBinaryIOUnencrypted(t *testing.T) {
	buf := new(bytes.Buffer)
	w := keyset.NewBinaryWriter(buf)
	r := keyset.NewBinaryReader(buf)

	manager := testutil.NewHMACKeysetManager()
	h, err := manager.Handle()
	if h == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}

	ks1 := testkeyset.KeysetMaterial(h)
	if err := w.Write(ks1); err != nil {
		t.Fatalf("cannot write keyset: %v", err)
	}

	ks2, err := r.Read()
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}

	if !proto.Equal(ks1, ks2) {
		t.Errorf("written keyset (%s) doesn't match read keyset (%s)", ks1, ks2)
	}
}

func TestBinaryIOEncrypted(t *testing.T) {
	buf := new(bytes.Buffer)
	w := keyset.NewBinaryWriter(buf)
	r := keyset.NewBinaryReader(buf)

	kse1 := &tinkpb.EncryptedKeyset{EncryptedKeyset: []byte(strings.Repeat("A", 32))}

	if err := w.WriteEncrypted(kse1); err != nil {
		t.Fatalf("cannot write encrypted keyset: %v", err)
	}

	kse2, err := r.ReadEncrypted()
	if err != nil {
		t.Fatalf("cannot read encrypted keyset: %v", err)
	}

	if !proto.Equal(kse1, kse2) {
		t.Errorf("written encrypted keyset (%s) doesn't match read encrypted keyset (%s)", kse1, kse2)
	}
}
