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
//
////////////////////////////////////////////////////////////////////////////////

package aead_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testutil"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNewKeyMultipleTimes(t *testing.T) {
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
		k, _ := keyManager.NewKey(keyTemplate.Value)
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

func TestNewKeyWithCorruptedFormat(t *testing.T) {
	keyTemplate := new(tinkpb.KeyTemplate)

	keyTemplate.TypeUrl = testutil.AESCTRHMACAEADTypeURL
	keyTemplate.Value = make([]byte, 128)

	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC-AEAD key manager: %s", err)
	}

	_, err = keyManager.NewKey(keyTemplate.Value)
	if err == nil {
		t.Error("NewKey got: success, want: error due to corrupted format")
	}

	_, err = keyManager.NewKeyData(keyTemplate.Value)
	if err == nil {
		t.Error("NewKeyData got: success, want: error due to corrupted format")
	}
}
