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
//
////////////////////////////////////////////////////////////////////////////////

package signature_test

import (
	"testing"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testutil"
)

func TestSignatureInit(t *testing.T) {
	// Check that the ECDSA signer key manager is in the global registry.
	if _, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Check that the ECDSA verifier key manager is in the global registry.
	if _, err := registry.GetKeyManager(testutil.ECDSAVerifierTypeURL); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
