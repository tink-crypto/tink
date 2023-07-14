// Copyright 2019 Google LLC
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

package hybrid_test

import (
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
)

// TODO(b/243759652): Move to hybrid_factory_test.go.
func TestBHybridDecrypt(t *testing.T) {
	manager := keyset.NewManager()
	id, err := manager.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	err = manager.SetPrimary(id)
	if err != nil {
		t.Fatalf("manager.SetPrimary gives err = '%v', want nil", err)
	}
	_, err = manager.Add(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle gives err = '%v', want nil", err)
	}

	if _, err := hybrid.NewHybridDecrypt(handle); err == nil {
		t.Error("hybrid.NewHybridDecrypt err = nil, want err")
	}
}

func TestBHybridEncrypt(t *testing.T) {
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle gives err = '%v', want nil", err)
	}
	pub, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public gives err = '%v', want nil", err)
	}
	manager := keyset.NewManagerFromHandle(pub)
	_, err = manager.Add(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	mixedHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle gives err = '%v', want nil", err)
	}
	if _, err := hybrid.NewHybridEncrypt(mixedHandle); err == nil {
		t.Error("hybrid.NewHybridDecrypt err = nil, want err")
	}
}
