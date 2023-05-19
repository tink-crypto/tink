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
	"github.com/google/tink/go/keyderivation"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/subtle/random"
	prfderpb "github.com/google/tink/go/proto/prf_based_deriver_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestWrappedKeysetDeriver(t *testing.T) {
	// Construct deriving keyset handle containing one key.
	aes128GCMKeyFormat, err := proto.Marshal(&prfderpb.PrfBasedDeriverKeyFormat{
		PrfKeyTemplate: prf.HKDFSHA256PRFKeyTemplate(),
		Params: &prfderpb.PrfBasedDeriverParams{
			DerivedKeyTemplate: aead.AES128GCMKeyTemplate(),
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal(aes128GCMKeyFormat) err = %v, want nil", err)
	}
	singleKeyHandle, err := keyset.NewHandle(&tinkpb.KeyTemplate{
		TypeUrl:          prfBasedDeriverTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            aes128GCMKeyFormat,
	})
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}

	// Construct deriving keyset handle containing three keys.
	xChaChaKeyFormat, err := proto.Marshal(&prfderpb.PrfBasedDeriverKeyFormat{
		PrfKeyTemplate: prf.HKDFSHA256PRFKeyTemplate(),
		Params: &prfderpb.PrfBasedDeriverParams{
			DerivedKeyTemplate: aead.XChaCha20Poly1305KeyTemplate(),
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal(xChaChaKeyFormat) err = %v, want nil", err)
	}
	aes256GCMKeyFormat, err := proto.Marshal(&prfderpb.PrfBasedDeriverKeyFormat{
		PrfKeyTemplate: prf.HKDFSHA256PRFKeyTemplate(),
		Params: &prfderpb.PrfBasedDeriverParams{
			DerivedKeyTemplate: aead.AES256GCMKeyTemplate(),
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal(aes256GCMKeyFormat) err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	aes128GCMKeyID, err := manager.Add(&tinkpb.KeyTemplate{
		TypeUrl:          prfBasedDeriverTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            aes128GCMKeyFormat,
	})
	if err != nil {
		t.Fatalf("manager.Add(aes128GCMTemplate) err = %v, want nil", err)
	}
	if err := manager.SetPrimary(aes128GCMKeyID); err != nil {
		t.Fatalf("manager.SetPrimary() err = %v, want nil", err)
	}
	if _, err := manager.Add(&tinkpb.KeyTemplate{
		TypeUrl:          prfBasedDeriverTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		Value:            xChaChaKeyFormat,
	}); err != nil {
		t.Fatalf("manager.Add(xChaChaTemplate) err = %v, want nil", err)
	}
	if _, err := manager.Add(&tinkpb.KeyTemplate{
		TypeUrl:          prfBasedDeriverTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
		Value:            aes256GCMKeyFormat,
	}); err != nil {
		t.Fatalf("manager.Add(aes256GCMTemplate) err = %v, want nil", err)
	}
	multipleKeysHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	if got, want := len(multipleKeysHandle.KeysetInfo().GetKeyInfo()), 3; got != want {
		t.Fatalf("len(multipleKeysHandle) = %d, want %d", got, want)
	}

	for _, test := range []struct {
		name         string
		handle       *keyset.Handle
		wantTypeURLs []string
	}{
		{
			name:   "single key",
			handle: singleKeyHandle,
			wantTypeURLs: []string{
				"type.googleapis.com/google.crypto.tink.AesGcmKey",
			},
		},
		{
			name:   "multiple keys",
			handle: multipleKeysHandle,
			wantTypeURLs: []string{
				"type.googleapis.com/google.crypto.tink.AesGcmKey",
				"type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
				"type.googleapis.com/google.crypto.tink.AesGcmKey",
			},
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
			if len(derivedKeyInfo) != len(test.wantTypeURLs) {
				t.Errorf("number of derived keys = %d, want %d", len(derivedKeyInfo), len(keyInfo))
			}

			// Verify derived keys.
			hasPrimaryKey := false
			for i, derivedKey := range derivedKeyInfo {
				derivingKey := keyInfo[i]
				if got, want := derivedKey.GetOutputPrefixType(), derivingKey.GetOutputPrefixType(); got != want {
					t.Errorf("GetOutputPrefixType() = %s, want %s", got, want)
				}
				if got, want := derivedKey.GetKeyId(), derivingKey.GetKeyId(); got != want {
					t.Errorf("GetKeyId() = %d, want %d", got, want)
				}
				if got, want := derivedKey.GetTypeUrl(), test.wantTypeURLs[i]; got != want {
					t.Errorf("GetTypeUrl() = %q, want %q", got, want)
				}
				if got, want := derivedKey.GetStatus(), derivingKey.GetStatus(); got != want {
					t.Errorf("GetStatus() = %s, want %s", got, want)
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
