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
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
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
	associatedData := random.GetRandomBytes(32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a pipe for communication between the encrypting writer and
		// decrypting reader.
		r, w := io.Pipe()
		defer r.Close()

		// Repeatedly encrypt the plaintext and write the ciphertext to a pipe.
		go func() {
			const writeAtLeast = 1 << 30 // 1 GiB

			enc, err := encCipher.NewEncryptingWriter(w, associatedData)
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
		dec, err := decCipher.NewDecryptingReader(r, associatedData)
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

func TestUnreaderUnread(t *testing.T) {
	original := make([]byte, 4096)
	if _, err := io.ReadFull(rand.Reader, original); err != nil {
		t.Fatalf("Failed to fill buffer with random bytes: %v", err)
	}

	u := &unreader{r: bytes.NewReader(original)}
	got, err := io.ReadAll(u)
	if err != nil {
		t.Errorf("First io.ReadAll(%T) failed unexpectedly: %v", u, err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("First io.ReadAll(%T) got %d bytes, want %d bytes that match the original random data.\nGot: %X\nWant: %X", u, len(got), len(original), got, original)
	}

	u.unread()
	got, err = io.ReadAll(u)
	if err != nil {
		t.Errorf("After %T.unread(), io.ReadAll(%T) failed unexpectedly: %v", u, u, err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("After %T.unread(), io.ReadAll(%T) got %d bytes, want %d bytes that match the original random data.\nGot: %X\nWant: %X", u, u, len(got), len(original), got, original)
	}
}

func TestUnreader(t *testing.T) {
	// Repeating sequence of characters '0' through '9' makes it easy to see
	// holes or repeated data.
	original := make([]byte, 100)
	for i := range original {
		original[i] = '0' + byte(i%10)
	}

	type step struct {
		read    int  // If set, read the given number of bytes exactly.
		unread  bool // If true, call unread().
		disable bool // If true, call disable().
	}
	tcs := []struct {
		name  string
		steps []step
	}{
		{"Read2UnreadRead4Unread", []step{{read: 2}, {unread: true}, {read: 4}, {unread: true}}},
		{"Read4UnreadRead2Unread", []step{{read: 4}, {unread: true}, {read: 2}, {unread: true}}},
		{"Read3UnreadRead3Unread", []step{{read: 3}, {unread: true}, {read: 3}, {unread: true}}},
		{"Read3Disable", []step{{read: 3}, {disable: true}}},
		{"Read2UnreadRead4Disable", []step{{read: 2}, {unread: true}, {read: 4}, {disable: true}}},
		{"Read4UnreadRead2Disable", []step{{read: 4}, {unread: true}, {read: 2}, {disable: true}}},
		{"Read3UnreadRead3Disable", []step{{read: 3}, {unread: true}, {read: 3}, {disable: true}}},
		{"Read2UnreadDisable", []step{{read: 2}, {unread: true}, {disable: true}}},
		{"Read4UnreadDisable", []step{{read: 4}, {unread: true}, {disable: true}}},
		{"ReadAllUnread", []step{{read: len(original)}, {unread: true}}},
		{"ReadAllDisable", []step{{read: len(original)}, {disable: true}}},
		{"Unread", []step{{unread: true}}},
		{"Disable", []step{{disable: true}}},
		{"UnreadDisable", []step{{unread: true}, {disable: true}}},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			u := &unreader{r: bytes.NewReader(original)}
			var (
				after []string
				pos   int
			)
			// Explains what happened before the failure.
			prefix := func() string {
				if after == nil {
					return ""
				}
				return fmt.Sprintf("After %s, ", strings.Join(after, "+"))
			}
			for _, s := range tc.steps {
				if s.read != 0 {
					buf := make([]byte, s.read)
					if _, err := io.ReadFull(u, buf); err != nil {
						t.Fatalf("%sio.ReadFull(%T, %d byte buffer) failed unexpectedly: %v", prefix(), u, s.read, err)
					}
					if want := original[pos : pos+s.read]; !bytes.Equal(buf, want) {
						t.Fatalf("%sio.ReadFull(%T, %d byte buffer) got %q, want %q", prefix(), u, s.read, buf, want)
					}
					after = append(after, fmt.Sprintf("Read(%d bytes)", s.read))
					pos += s.read
				}
				if s.disable {
					u.disable()
					after = append(after, "disable()")
				}
				if s.unread {
					u.unread()
					after = append(after, "unread()")
					pos = 0
				}
			}
			got, err := io.ReadAll(u)
			if err != nil {
				t.Fatalf("%sio.ReadAll(%T) failed unexpectedly: %v", prefix(), u, err)
			}
			if want := original[pos:]; !bytes.Equal(want, got) {
				t.Errorf("%sio.ReadAll(%T) got %q, want %q", prefix(), u, got, want)
			}
		})
	}
}
