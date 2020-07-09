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

package mac_test

import (
	"log"
	"testing"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testutil"
)

func TestMacInit(t *testing.T) {
	_, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	_, err = registry.GetKeyManager(testutil.AESCMACTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func Example() {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	m, err := mac.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	mac, err := m.ComputeMAC([]byte("this data needs to be MACed"))
	if err != nil {
		log.Fatal(err)
	}

	if m.VerifyMAC(mac, []byte("this data needs to be MACed")); err != nil {
		log.Fatal(err)
	}

	// Output:
}
