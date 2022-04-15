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

package streamingaead

import (
	"io"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func BenchmarkDecryptReader(b *testing.B) {
	b.ReportAllocs()

	// Create a Streaming AEAD primitive using a full keyset.
	decKeyset := testutil.NewTestAESGCMHKDFKeyset()
	decKeysetHandle, err := testkeyset.NewHandle(decKeyset)
	if err != nil {
		b.Fatalf("Failed creating keyset handle: %v", err)
	}
	decCipher, err := New(decKeysetHandle)
	if err != nil {
		b.Errorf("streamingaead.New failed: %v", err)
	}

	// Extract the raw key from the keyset and create a Streaming AEAD primitive
	// using only that key.
	//
	// testutil.NewTestAESGCMHKDFKeyset() places a raw key at position 1.
	rawKey := decKeyset.Key[1]
	if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		b.Fatalf("Expected a raw key.")
	}
	encKeyset := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
	encKeysetHandle, err := testkeyset.NewHandle(encKeyset)
	if err != nil {
		b.Fatalf("Failed creating keyset handle: %v", err)
	}
	encCipher, err := New(encKeysetHandle)
	if err != nil {
		b.Fatalf("streamingaead.New failed: %v", err)
	}

	plaintext := random.GetRandomBytes(8)
	additionalData := random.GetRandomBytes(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a pipe for communication between the encrypting writer and
		// decrypting reader.
		r, w := io.Pipe()
		defer r.Close()

		// Repeatedly encrypt the plaintext and write the ciphertext to a pipe.
		go func() {
			const writeAtLeast = 1 << 30 // 1 GiB

			enc, err := encCipher.NewEncryptingWriter(w, additionalData)
			if err != nil {
				b.Errorf("Cannot create encrypt writer: %v", err)
				return
			}

			for i := 0; i < writeAtLeast; i += len(plaintext) {
				if _, err := enc.Write(plaintext); err != nil {
					b.Errorf("Error encrypting data: %v", err)
					return
				}
			}
			if err := enc.Close(); err != nil {
				b.Errorf("Error closing encrypting writer: %v", err)
				return
			}
			if err := w.Close(); err != nil {
				b.Errorf("Error closing pipe: %v", err)
				return
			}
		}()

		// Decrypt the ciphertext in small chunks.
		dec, err := decCipher.NewDecryptingReader(r, additionalData)
		if err != nil {
			b.Fatalf("Cannot create decrypt reader: %v", err)
		}
		buf := make([]byte, 16384) // 16 KiB
		for {
			_, err := dec.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatalf("Error decrypting data: %v", err)
			}
		}
	}
}
