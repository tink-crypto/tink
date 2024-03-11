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

package hybrid_test

import (
	"testing"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Benchmarks for Hybrid Encryption algorithms.

const benchmarkPlaintextSize = 1 * 1024
const benchmarkContextInfoSize = 256

var benchmarkTestCases = []struct {
	name     string
	template *tinkpb.KeyTemplate
}{
	{
		name:     "HPKE_X25519_AES128GCM",
		template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template(),
	}, {
		name:     "HPKE_X25519_Chacha20Poly1305",
		template: hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template(),
	}, {
		name:     "ECIES_P256_AES128GCM",
		template: hybrid.ECIESHKDFAES128GCMKeyTemplate(),
	}, {
		name:     "ECIES_P256_AES128CTRHMAC",
		template: hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate(),
	}, {
		name:     "ECIES_P384_AES128GCM",
		template: eciesP384AES256GCMKeyTemplate(),
	}, {
		name:     "ECIES_P521_AES128GCM",
		template: eciesP521AES256GCMKeyTemplate(),
	}, {
		name:     "ECIES_P256_AESSIV",
		template: eciesP256AESSIVKeyTemplate(),
	},
}

func BenchmarkEncrypt(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			privHandle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			pubHandle, err := privHandle.Public()
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := hybrid.NewHybridEncrypt(pubHandle)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := random.GetRandomBytes(benchmarkPlaintextSize)
			contextInfo := random.GetRandomBytes(benchmarkContextInfoSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = primitive.Encrypt(plaintext, contextInfo)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, tc := range benchmarkTestCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			privHandle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			pubHandle, err := privHandle.Public()
			if err != nil {
				b.Fatal(err)
			}
			plaintext := random.GetRandomBytes(benchmarkPlaintextSize)
			contextInfo := random.GetRandomBytes(benchmarkContextInfoSize)
			encrypter, err := hybrid.NewHybridEncrypt(pubHandle)
			if err != nil {
				b.Fatal(err)
			}
			ciphertext, err := encrypter.Encrypt(plaintext, contextInfo)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := hybrid.NewHybridDecrypt(privHandle)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = primitive.Decrypt(ciphertext, contextInfo)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
