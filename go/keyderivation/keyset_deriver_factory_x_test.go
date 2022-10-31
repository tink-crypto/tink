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

package keyderivation_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyderivation/internal/streamingprf"
	"github.com/google/tink/go/keyderivation"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	prfderpb "github.com/google/tink/go/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestWrappedKeysetDeriver(t *testing.T) {
	// Construct a deriving keyset handle containing one key.
	sha256AES128GCMkeyFormat := &prfderpb.PrfBasedDeriverKeyFormat{
		PrfKeyTemplate: streamingprf.HKDFSHA256RawKeyTemplate(),
		Params: &prfderpb.PrfBasedDeriverParams{
			DerivedKeyTemplate: aead.AES128GCMKeyTemplate(),
		},
	}
	serializedKeyFormat, err := proto.Marshal(sha256AES128GCMkeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", sha256AES128GCMkeyFormat, err)
	}
	template := &tinkpb.KeyTemplate{
		TypeUrl:          prfBasedDeriverTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            serializedKeyFormat,
	}
	singleKeyHandle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}

	// Construct a deriving keyset handle containing two different types of keys.
	sha512AES256GCMNoPrefixkeyFormat := &prfderpb.PrfBasedDeriverKeyFormat{
		PrfKeyTemplate: streamingprf.HKDFSHA512RawKeyTemplate(),
		Params: &prfderpb.PrfBasedDeriverParams{
			DerivedKeyTemplate: aead.AES256GCMNoPrefixKeyTemplate(),
		},
	}
	serializedKeyFormat, err = proto.Marshal(sha512AES256GCMNoPrefixkeyFormat)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", sha512AES256GCMNoPrefixkeyFormat, err)
	}
	template = &tinkpb.KeyTemplate{
		TypeUrl:          prfBasedDeriverTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            serializedKeyFormat,
	}
	manager := keyset.NewManagerFromHandle(singleKeyHandle)
	if _, err := manager.Add(template); err != nil {
		t.Fatalf("manager.Add() err = %v, want nil", err)
	}
	multipleKeysHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err %v, want nil", err)
	}

	for _, test := range []struct {
		name   string
		handle *keyset.Handle
	}{
		{
			name:   "single key",
			handle: singleKeyHandle,
		},
		{
			name:   "multiple keys",
			handle: multipleKeysHandle,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Derive keyset handle.
			kd, err := keyderivation.New(test.handle)
			if err != nil {
				t.Fatalf("keyderivation.New() err = %v, want nil", err)
			}
			derivedHandle, err := kd.DeriveKeyset([]byte("salt"))
			if err != nil {
				t.Fatalf("DeriveKeyset() err = %v, want nil", err)
			}

			// Verify number of derived keys = number of deriving keys.
			derivedKeyInfo := derivedHandle.KeysetInfo().GetKeyInfo()
			keyInfo := test.handle.KeysetInfo().GetKeyInfo()
			if len(derivedKeyInfo) != len(keyInfo) {
				t.Errorf("number of derived keys = %d, want %d", len(derivedKeyInfo), len(keyInfo))
			}

			// Verify each derived key.
			hasPrimaryKey := false
			for _, derivedKey := range derivedKeyInfo {
				if derivedKey.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
					t.Errorf("GetOutputPrefixType() = %s, want %s", derivedKey.GetOutputPrefixType(), tinkpb.OutputPrefixType_RAW)
				}
				// Verify each derived key has the same key ID as a deriving key.
				hasMatchingDerivingKey := false
				for _, key := range keyInfo {
					if key.GetKeyId() == derivedKey.GetKeyId() {
						hasMatchingDerivingKey = true
					} else {
						continue
					}
					if got, want := derivedKey.GetTypeUrl(), "type.googleapis.com/google.crypto.tink.AesGcmKey"; got != want {
						t.Errorf("GetTypeUrl() = %q, want %q", got, want)
					}
					if derivedKey.GetStatus() != key.GetStatus() {
						t.Errorf("GetStatus() = %s, want %s", derivedKey.GetStatus(), key.GetStatus())
					}
				}
				if !hasMatchingDerivingKey {
					t.Errorf("derived key has no matching deriving key")
				}
				if derivedKey.GetKeyId() == derivedHandle.KeysetInfo().GetPrimaryKeyId() {
					hasPrimaryKey = true
				}
			}
			if !hasPrimaryKey {
				t.Errorf("derived keyset has no primary key")
			}

			// Verify derived keyset handle works for AEAD.
			pt := random.GetRandomBytes(16)
			ad := random.GetRandomBytes(4)
			a, err := aead.New(derivedHandle)
			if err != nil {
				t.Fatalf("aead.New() err = %v, want nil", err)
			}
			ct, err := a.Encrypt(pt, ad)
			if err != nil {
				t.Fatalf("Encrypt() err = %v, want nil", err)
			}
			gotPT, err := a.Decrypt(ct, ad)
			if err != nil {
				t.Fatalf("Decrypt() err = %v, want nil", err)
			}
			if !bytes.Equal(gotPT, pt) {
				t.Errorf("Decrypt() = %v, want %v", gotPT, pt)
			}
		})
	}
}

func TestNewRejectsNilKeysetHandle(t *testing.T) {
	if _, err := keyderivation.New(nil); err == nil {
		t.Error("keyderivation.New() err = nil, want non-nil")
	}
}

func TestNewRejectsIncorrectKey(t *testing.T) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	if _, err := keyderivation.New(kh); err == nil {
		t.Error("keyderivation.New() err = nil, want non-nil")
	}
}
