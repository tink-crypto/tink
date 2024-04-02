// Copyright 2018 Google LLC
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

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testutil"
	ctrpb "github.com/google/tink/go/proto/aes_ctr_go_proto"
	aeadpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
)

func TestAESCTRHMACNewKeyMultipleTimes(t *testing.T) {
	keyTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	aeadKeyFormat := new(ctrhmacpb.AesCtrHmacAeadKeyFormat)
	if err := proto.Unmarshal(keyTemplate.Value, aeadKeyFormat); err != nil {
		t.Fatalf("cannot unmarshal AES128CTRHMACSHA256 key template")
	}

	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC-AEAD key manager: %s", err)
	}

	keys := make(map[string]bool)
	const numTests = 24
	for i := 0; i < numTests/2; i++ {
		k, err := keyManager.NewKey(keyTemplate.Value)
		if err != nil {
			t.Fatalf("keyManager.NewKey() err = %q, want nil", err)
		}
		sk, err := proto.Marshal(k)
		if err != nil {
			t.Fatalf("cannot serialize key, error: %v", err)
		}

		key := new(ctrhmacpb.AesCtrHmacAeadKey)
		proto.Unmarshal(sk, key)

		keys[string(key.AesCtrKey.KeyValue)] = true
		keys[string(key.HmacKey.KeyValue)] = true
		if len(key.AesCtrKey.KeyValue) != 16 {
			t.Errorf("unexpected AES key size, got: %d, want: 16", len(key.AesCtrKey.KeyValue))
		}
		if len(key.HmacKey.KeyValue) != 32 {
			t.Errorf("unexpected HMAC key size, got: %d, want: 32", len(key.HmacKey.KeyValue))
		}
	}
	if len(keys) != numTests {
		t.Errorf("unexpected number of keys in set, got: %d, want: %d", len(keys), numTests)
	}
}

func TestAESCTRHMACNewKeyWithInvalidSerializedKeyFormat(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC-AEAD key manager: %s", err)
	}

	testcases := []struct {
		name                string
		serializedKeyFormat []byte
		keyFormat           *ctrhmacpb.AesCtrHmacAeadKeyFormat
	}{
		{
			name:                "empty",
			serializedKeyFormat: make([]byte, 128),
		},
		{
			name: "params_unset",
			keyFormat: &ctrhmacpb.AesCtrHmacAeadKeyFormat{
				AesCtrKeyFormat: &ctrpb.AesCtrKeyFormat{
					Params:  nil,
					KeySize: 32,
				},
				HmacKeyFormat: &hmacpb.HmacKeyFormat{
					Params:  nil,
					KeySize: 32,
				},
			},
		},
		{
			name: "nested_key_formats_unset",
			keyFormat: &ctrhmacpb.AesCtrHmacAeadKeyFormat{
				AesCtrKeyFormat: nil,
				HmacKeyFormat:   nil,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			serializedKeyFormat := tc.serializedKeyFormat
			if serializedKeyFormat == nil {
				var err error
				serializedKeyFormat, err = proto.Marshal(tc.keyFormat)
				if err != nil {
					t.Fatalf("failed to marshal key format: %s", err)
				}
			}

			_, err = keyManager.NewKey(serializedKeyFormat)
			if err == nil {
				t.Error("NewKey() err = nil, want not error")
			}

			_, err = keyManager.NewKeyData(serializedKeyFormat)
			if err == nil {
				t.Error("NewKeyData() err = nil, want error")
			}
		})
	}
}

func TestAESCTRHMACPrimitive(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC-AEAD key manager: %s", err)
	}

	key := &aeadpb.AesCtrHmacAeadKey{
		Version: 0,
		AesCtrKey: &ctrpb.AesCtrKey{
			Version:  0,
			KeyValue: make([]byte, 32),
			Params:   &ctrpb.AesCtrParams{IvSize: 16},
		},
		HmacKey: &hmacpb.HmacKey{
			Version:  0,
			KeyValue: make([]byte, 32),
			Params:   &hmacpb.HmacParams{Hash: commonpb.HashType_SHA256, TagSize: 32},
		},
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}

	_, err = keyManager.Primitive(serializedKey)
	if err != nil {
		t.Errorf("Primitive() err = %v, want nil", err)
	}
}

func TestAESCTRHMACPrimitiveWithInvalidKey(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC-AEAD key manager: %s", err)
	}

	testcases := []struct {
		name string
		key  *ctrhmacpb.AesCtrHmacAeadKey
	}{
		{
			name: "nil_nested_keys",
			key: &aeadpb.AesCtrHmacAeadKey{
				Version:   0,
				AesCtrKey: nil,
				HmacKey:   nil,
			},
		},
		{
			name: "nil_key_params",
			key: &aeadpb.AesCtrHmacAeadKey{
				Version: 0,
				AesCtrKey: &ctrpb.AesCtrKey{
					Version:  0,
					KeyValue: make([]byte, 32),
					Params:   nil,
				},
				HmacKey: &hmacpb.HmacKey{
					Version:  0,
					KeyValue: make([]byte, 32),
					Params:   nil,
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Fatalf("failed to marshal key: %s", err)
			}

			_, err = keyManager.Primitive(serializedKey)
			if err == nil {
				t.Error("Primitive() err = nil, want error")
			}
		})
	}
}
