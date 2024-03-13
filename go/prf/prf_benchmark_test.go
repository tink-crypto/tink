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

package prf_test

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Benchmarks for PRF algorithms.

func BenchmarkComputePRF(b *testing.B) {
	const (
		outputLength = 16
	)
	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
		dataSize uint32
	}{
		{
			name:     "HMAC_SHA256_PRF_16",
			template: prf.HMACSHA256PRFKeyTemplate(),
			dataSize: 16,
		}, {
			name:     "HMAC_SHA256_PRF_16k",
			template: prf.HMACSHA256PRFKeyTemplate(),
			dataSize: 16 * 1024,
		}, {
			name:     "HMAC_SHA512_PRF_16",
			template: prf.HMACSHA512PRFKeyTemplate(),
			dataSize: 16,
		}, {
			name:     "HMAC_SHA512_PRF_16k",
			template: prf.HMACSHA512PRFKeyTemplate(),
			dataSize: 16 * 1024,
		}, {
			name:     "HKDF_SHA256_16",
			template: prf.HKDFSHA256PRFKeyTemplate(),
			dataSize: 16,
		}, {
			name:     "HKDF_SHA256_16k",
			template: prf.HKDFSHA256PRFKeyTemplate(),
			dataSize: 16 * 1024,
		}, {
			name:     "AES_CMAC_PRF_16",
			template: prf.AESCMACPRFKeyTemplate(),
			dataSize: 16,
		}, {
			name:     "AES_CMAC_PRF_16k",
			template: prf.AESCMACPRFKeyTemplate(),
			dataSize: 16 * 1024,
		},
	}
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := prf.NewPRFSet(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(tc.dataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.ComputePrimaryPRF(data, outputLength)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
