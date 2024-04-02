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

package aead_test

import (
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Benchmarks for AEAD algorithms.

func BenchmarkEncryptDecrypt(b *testing.B) {
	const (
		plaintextSize      = 16 * 1024
		associatedDataSize = 256
	)

	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128_GCM",
			template: aead.AES128GCMKeyTemplate(),
		}, {
			name:     "AES256_GCM",
			template: aead.AES256GCMKeyTemplate(),
		}, {
			name:     "CHACHA20_POLY1305",
			template: aead.ChaCha20Poly1305KeyTemplate(),
		}, {
			name:     "XCHACHA20_POLY1305",
			template: aead.XChaCha20Poly1305KeyTemplate(),
		}, {
			name:     "AES128_CTR_HMAC",
			template: aead.AES128CTRHMACSHA256KeyTemplate(),
		}, {
			name:     "AES256_CTR_HMAC",
			template: aead.AES256CTRHMACSHA256KeyTemplate(),
		}, {
			name:     "AES128_GCM_SIV",
			template: aead.AES128GCMSIVKeyTemplate(),
		}, {
			name:     "AES256_GCM_SIV",
			template: aead.AES256GCMSIVKeyTemplate(),
		},
	}
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			handle, err := keyset.NewHandle(tc.template)
			if err != nil {
				b.Fatal(err)
			}
			primitive, err := aead.New(handle)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := random.GetRandomBytes(plaintextSize)
			associatedData := random.GetRandomBytes(associatedDataSize)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ciphertext, err := primitive.Encrypt(plaintext, associatedData)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = primitive.Decrypt(ciphertext, associatedData); err != nil {
					b.Error(err)
				}
			}
		})
	}
}
