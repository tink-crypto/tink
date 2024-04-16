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

package mac_test

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Benchmarks for MAC algorithms.

var benchmarkTestCases = []struct {
	name     string
	template *tinkpb.KeyTemplate
	dataSize uint32
}{
	{
		name:     "HMAC_SHA256_16",
		template: mac.HMACSHA256Tag128KeyTemplate(),
		dataSize: 16,
	}, {
		name:     "HMAC_SHA512_16",
		template: mac.HMACSHA512Tag256KeyTemplate(),
		dataSize: 16,
	}, {
		name:     "AES_CMAC_16",
		template: mac.AESCMACTag128KeyTemplate(),
		dataSize: 16,
	}, {
		name:     "HMAC_SHA256_16k",
		template: mac.HMACSHA256Tag128KeyTemplate(),
		dataSize: 16 * 1024,
	}, {
		name:     "HMAC_SHA512_16k",
		template: mac.HMACSHA512Tag256KeyTemplate(),
		dataSize: 16 * 1024,
	}, {
		name:     "AES_CMAC_16k",
		template: mac.AESCMACTag128KeyTemplate(),
		dataSize: 16 * 1024,
	},
}

func BenchmarkComputeMac(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := mac.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(tc.dataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := primitive.ComputeMAC(data)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

func BenchmarkVerifyMac(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := mac.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(tc.dataSize)
			tag, err := primitive.ComputeMAC(data)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err = primitive.VerifyMAC(tag, data); err != nil {
					b.Error(err)
				}
			}
		})
	}
}
