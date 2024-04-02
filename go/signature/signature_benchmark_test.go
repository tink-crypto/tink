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

package signature_test

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Benchmarks for Signature algorithms.

const benchmarkDataSize = 16 * 1024

var benchmarkTestCases = []struct {
	name     string
	template *tinkpb.KeyTemplate
}{
	{
		name:     "RSA_SSA_PKCS1_3072",
		template: signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template(),
	}, {
		name:     "RSA_SSA_PSS_3072",
		template: signature.RSA_SSA_PSS_3072_SHA256_32_F4_Key_Template(),
	}, {
		name:     "RSA_SSA_PKCS1_4096",
		template: signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template(),
	}, {
		name:     "RSA_SSA_PSS_4096",
		template: signature.RSA_SSA_PSS_4096_SHA512_64_F4_Key_Template(),
	}, {
		name:     "ECDSA_P256",
		template: signature.ECDSAP256KeyTemplate(),
	}, {
		name:     "ECDSA_P384",
		template: signature.ECDSAP384SHA384KeyTemplate(),
	}, {
		name:     "ECDSA_P521",
		template: signature.ECDSAP521KeyTemplate(),
	}, {
		name:     "ED25519",
		template: signature.ED25519KeyTemplate(),
	},
}

func BenchmarkSign(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := signature.NewSigner(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(benchmarkDataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = primitive.Sign(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			signer, err := signature.NewSigner(handle)
			if err != nil {
				b.Fatal(err)
			}
			data := random.GetRandomBytes(benchmarkDataSize)
			sig, err := signer.Sign(data)
			if err != nil {
				b.Fatal(err)
			}
			publicHandle, err := handle.Public()
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := signature.NewVerifier(publicHandle)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err = primitive.Verify(sig, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
