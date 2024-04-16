// Copyright 2024 Google LLC
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
// //////////////////////////////////////////////////////////////////////////////

package daead_test

import (
	"testing"

	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Benchmarks for Deterministic AEAD algorithms.

func BenchmarkAESSIV(b *testing.B) {
	const (
		plaintextSize      = 16 * 1024
		associatedDataSize = 256
	)
	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES256_SIV",
			template: daead.AESSIVKeyTemplate(),
		},
	}
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := daead.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := random.GetRandomBytes(plaintextSize)
			associatedData := random.GetRandomBytes(associatedDataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ciphertext, err := primitive.EncryptDeterministically(plaintext, associatedData)
				if err != nil {
					b.Fatal(err)
				}
				_, err = primitive.DecryptDeterministically(ciphertext, associatedData)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}
