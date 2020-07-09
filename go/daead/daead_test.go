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

package daead_test

import (
	"bytes"
	"log"
	"testing"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testutil"
)

func Example() {
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	d, err := daead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	ct1, err := d.EncryptDeterministically([]byte("this data needs to be encrypted"), []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = d.DecryptDeterministically(ct1, []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}

	ct2, err := d.EncryptDeterministically([]byte("this data needs to be encrypted"), []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(ct1, ct2) {
		log.Fatal("ct1 != ct2")
	}

	// Output:
}

func TestDeterministicAEADInit(t *testing.T) {
	// Check for AES-SIV key manager.
	_, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
