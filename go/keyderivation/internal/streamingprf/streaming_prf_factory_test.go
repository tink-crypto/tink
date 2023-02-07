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
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNew(t *testing.T) {
	keyData, err := registry.NewKeyData(prf.HKDFSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("registry.NewKeyData() err = %v", err)
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: 119,
		Key: []*tinkpb.Keyset_Key{
			&tinkpb.Keyset_Key{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            119,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(ks) err = %v, want nil", err)
	}
	prf, err := streamingprf.New(handle)
	if err != nil {
		t.Fatalf("streamingprf.New() err = %v, want nil", err)
	}
	r, err := prf.Compute(random.GetRandomBytes(32))
	if err != nil {
		t.Fatalf("prf.Compute() err = %v, want nil", err)
	}
	limit := limitFromHash(t, commonpb.HashType_SHA256)
	out := make([]byte, limit)
	n, err := r.Read(out)
	if n != limit || err != nil {
		t.Errorf("Read() bytes = %d, want %d: %v", n, limit, err)
	}
}

func TestNewEqualToStreamingPRFPrimitive(t *testing.T) {
	streamingPRFKM := streamingprf.HKDFStreamingPRFKeyManager{}
	prfKM, err := registry.GetKeyManager(hkdfPRFTypeURL)
	if err != nil {
		t.Fatalf("GetKeyManager(%s) err = %v, want nil", hkdfPRFTypeURL, err)
	}
	for _, test := range []struct {
		name string
		hash commonpb.HashType
		salt []byte
	}{
		{
			name: "SHA256_nil_salt",
			hash: commonpb.HashType_SHA256,
		},
		{
			name: "SHA256_random_salt",
			hash: commonpb.HashType_SHA256,
			salt: random.GetRandomBytes(16),
		},
		{
			name: "SHA512_nil_salt",
			hash: commonpb.HashType_SHA512,
		},
		{
			name: "SHA512_random_salt",
			hash: commonpb.HashType_SHA512,
			salt: random.GetRandomBytes(16),
		},
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
			sharedKeyData, err := prfKM.NewKeyData(serializedKeyFormat)
			if err != nil {
				t.Fatalf("NewKeyData() err = %v, want nil", err)
			}

			// Use shared key data to create StreamingPRF using New().
			var primaryKeyID uint32 = 12
			handle, err := testkeyset.NewHandle(
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
			gotPRF, err := streamingprf.New(handle)
			if err != nil {
				t.Fatalf("streamingprf.New() err = %v, want nil", err)
			}

			// Use shared key data to create StreamingPRF using Primitive().
			p, err := streamingPRFKM.Primitive(sharedKeyData.GetValue())
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

func TestNewRejectsIncorrectKeysetHandle(t *testing.T) {
	if _, err := streamingprf.New(nil); err == nil {
		t.Error("streamingprf.New() err = nil, want non-nil")
	}

	aeadHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	if _, err := streamingprf.New(aeadHandle); err == nil {
		t.Error("streamingprf.New() err = nil, want non-nil")
	}
}

func TestNewRejectsInvalidKeysetHandle(t *testing.T) {
	keyData, err := registry.NewKeyData(prf.HKDFSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("registry.NewKeyData() err = %v", err)
	}
	for _, test := range []struct {
		name   string
		keyset *tinkpb.Keyset
	}{
		{
			"multiple raw keys",
			&tinkpb.Keyset{
				PrimaryKeyId: 119,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            119,
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            200,
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
				},
			},
		},
		{
			"various output prefix keys",
			&tinkpb.Keyset{
				PrimaryKeyId: 119,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            119,
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            200,
						OutputPrefixType: tinkpb.OutputPrefixType_TINK,
					},
				},
			},
		},
		{
			"invalid prefix type",
			&tinkpb.Keyset{
				PrimaryKeyId: 119,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_ENABLED,
						KeyId:            119,
						OutputPrefixType: tinkpb.OutputPrefixType_TINK,
					},
				},
			}},
		{
			"invalid status",
			&tinkpb.Keyset{
				PrimaryKeyId: 119,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_UNKNOWN_STATUS,
						KeyId:            119,
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
				},
			},
		},
		{
			"no primary key",
			&tinkpb.Keyset{
				PrimaryKeyId: 200,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyData:          keyData,
						Status:           tinkpb.KeyStatusType_UNKNOWN_STATUS,
						KeyId:            119,
						OutputPrefixType: tinkpb.OutputPrefixType_RAW,
					},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle, err := testkeyset.NewHandle(test.keyset)
			if err != nil {
				t.Fatalf("testkeyset.NewHandle(test.keyset) err = %v, want nil", err)
			}
			if _, err := streamingprf.New(handle); err == nil {
				t.Error("streamingprf.New() err = nil, want non-nil")
			}
		})
	}
}
