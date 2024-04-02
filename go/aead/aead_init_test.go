// Copyright 2023 Google LLC
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

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testutil"
)

func TestAEADInit(t *testing.T) {
	// Check that the AES-GCM key manager is in the global registry.
	_, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Check that the ChaCha20Poly1305 key manager is in the global registry.
	_, err = registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Check that the XChaCha20Poly1305 key manager is in the global registry.
	_, err = registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
