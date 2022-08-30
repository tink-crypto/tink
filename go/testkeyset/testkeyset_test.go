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

package testkeyset_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func makeKeyset(template *tinkpb.KeyTemplate) (*tinkpb.Keyset, error) {
	h, err := keyset.NewHandle(template)
	if err != nil {
		return nil, err
	}
	return insecurecleartextkeyset.KeysetMaterial(h), nil
}

func TestNewHandleCallsAreConsistent(t *testing.T) {
	ks, err := makeKeyset(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("makeKeyset(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}
	handle1, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %v, want nil", err)
	}
	p1, err := mac.New(handle1)
	if err != nil {
		t.Fatalf("mac.New(handle1) err = %v, want nil", err)
	}
	p2, err := mac.New(testkeyset.KeysetHandle(ks))
	if err != nil {
		t.Fatalf("mac.New(testkeyset.KeysetHandle(ks)) err = %v, want nil", err)
	}
	data := []byte("data")
	m1, err := p1.ComputeMAC(data)
	if err != nil {
		t.Fatalf("p1.ComputeMAC(data) err = %v, want nil", err)
	}
	m2, err := p2.ComputeMAC(data)
	if err != nil {
		t.Fatalf("p2.ComputeMAC(data) err = %v, want nil", err)
	}
	if !cmp.Equal(m1, m2) {
		t.Errorf("MAC mistmatch, got = %v, want %v", m1, m2)
	}
}
