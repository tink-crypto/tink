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
	"log"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testutil"
)

func Example() {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	ct, err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = a.Decrypt(ct, []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}

	// Output:
}

func TestAEADInit(t *testing.T) {
	// Check for AES-GCM key manager.
	_, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Check for ChaCha20Poly1305 key manager.
	_, err = registry.GetKeyManager(testutil.ChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// Check for XChaCha20Poly1305 key manager.
	_, err = registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
