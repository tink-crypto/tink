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
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyderivation/internal/streamingprf"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNew(t *testing.T) {
	for _, test := range []struct {
		name     string
		hash     commonpb.HashType
		template *tinkpb.KeyTemplate
	}{
		{"SHA256", commonpb.HashType_SHA256, streamingprf.HKDFSHA256RawKeyTemplate()},
		{"SHA512", commonpb.HashType_SHA512, streamingprf.HKDFSHA512RawKeyTemplate()},
	} {
		t.Run(test.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(test.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
			}
			prf, err := streamingprf.New(kh)
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

func TestNewEqualToStreamingPRFPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(hkdfStreamingPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfStreamingPRFTypeURL, err)
	}
	for _, test := range []struct {
		name string
		hash commonpb.HashType
		salt []byte
	}{
		{"SHA256", commonpb.HashType_SHA256, nil},
		{"SHA256/salt", commonpb.HashType_SHA256, random.GetRandomBytes(16)},
		{"SHA512", commonpb.HashType_SHA512, nil},
		{"SHA512/salt", commonpb.HashType_SHA512, random.GetRandomBytes(16)},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Construct shared key data.
			keyFormat := &hkdfpb.HkdfPrfKeyFormat{
				Params: &hkdfpb.HkdfPrfParams{
					Hash: test.hash,
					Salt: test.salt,
				},
				KeySize: 32,
				Version: 0,
			}
			serializedKeyFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyFormat, err)
			}
			sharedKeyData, err := km.NewKeyData(serializedKeyFormat)
			if err != nil {
				t.Fatalf("NewKeyData() err = %v, want nil", err)
			}

			// Use shared key data to create StreamingPRF using New().
			var primaryKeyID uint32 = 12
			kh, err := testkeyset.NewHandle(
				&tinkpb.Keyset{
					PrimaryKeyId: primaryKeyID,
					Key: []*tinkpb.Keyset_Key{
						&tinkpb.Keyset_Key{
							KeyData:          sharedKeyData,
							Status:           tinkpb.KeyStatusType_ENABLED,
							KeyId:            primaryKeyID,
							OutputPrefixType: tinkpb.OutputPrefixType_RAW,
						},
					},
				})
			if err != nil {
				t.Fatalf("testkeyset.NewHandle() err = %v, want nil", err)
			}
			gotPRF, err := streamingprf.New(kh)
			if err != nil {
				t.Fatalf("streamingprf.New() err = %v, want nil", err)
			}

			// Use shared key data to create StreamingPRF using Primitive().
			p, err := km.Primitive(sharedKeyData.GetValue())
			if err != nil {
				t.Fatalf("Primitive() err = %v, want nil", err)
			}
			wantPRF, ok := p.(streamingprf.StreamingPRF)
			if !ok {
				t.Fatal("primitive is not StreamingPRF")
			}

			// Verify both PRFs return the same results.
			limit := limitFromHash(t, test.hash)
			got, want := make([]byte, limit), make([]byte, limit)
			data := random.GetRandomBytes(32)
			{
				r, err := gotPRF.Compute(data)
				if err != nil {
					t.Fatalf("Compute() err = %v, want nil", err)
				}
				n, err := r.Read(got)
				if n != limit || err != nil {
					t.Fatalf("Read() bytes = %d, want %d: %v", n, limit, err)
				}
			}
			{
				r, err := wantPRF.Compute(data)
				if err != nil {
					t.Fatalf("Compute() err = %v, want nil", err)
				}
				n, err := r.Read(want)
				if n != limit || err != nil {
					t.Fatalf("Read() bytes = %d, want %d: %v", n, limit, err)
				}
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Read() = %v, want %v", got, want)
			}
		})
	}
}

func TestNewRejectsNilKeysetHandle(t *testing.T) {
	if _, err := streamingprf.New(nil); err == nil {
		t.Error("streamingprf.New() err = nil, want non-nil")
	}
}

func TestNewRejectsIncorrectKey(t *testing.T) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	if _, err := streamingprf.New(kh); err == nil {
		t.Error("streamingprf.New() err = nil, want non-nil")
	}
}
