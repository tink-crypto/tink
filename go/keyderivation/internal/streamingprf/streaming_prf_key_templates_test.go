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

package streamingprf_test

import (
	"testing"

	"github.com/google/tink/go/keyderivation/internal/streamingprf"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeyTemplates(t *testing.T) {
	for _, test := range []struct {
		name     string
		hash     commonpb.HashType
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "SHA256",
			hash:     commonpb.HashType_SHA256,
			template: streamingprf.HKDFSHA256RawKeyTemplate(),
		},
		{
			name:     "SHA512",
			hash:     commonpb.HashType_SHA512,
			template: streamingprf.HKDFSHA512RawKeyTemplate(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle, err := keyset.NewHandle(test.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
			}
			prf, err := streamingprf.New(handle)
			if err != nil {
				t.Errorf("streamingprf.New() err = %v, want nil", err)
			}
			r, err := prf.Compute(random.GetRandomBytes(32))
			if err != nil {
				t.Fatalf("prf.Compute() err = %v, want nil", err)
			}
			limit := limitFromHash(t, test.hash)
			out := make([]byte, limit)
			n, err := r.Read(out)
			if n != limit || err != nil {
				t.Errorf("Read() bytes = %d, want %d: %v", n, limit, err)
			}
		})
	}
}
