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
	"log"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
)

func Example() {
	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	khPub, err := khPriv.Public()
	if err != nil {
		log.Fatal(err)
	}

	enc, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		log.Fatal(err)
	}

	ct, err := enc.Encrypt([]byte("this data needs to be encrypted"), []byte("context info"))
	if err != nil {
		log.Fatal(err)
	}

	dec, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		log.Fatal(err)
	}

	_, err = dec.Decrypt(ct, []byte("context info"))
	if err != nil {
		log.Fatal(err)
	}

	// Output:
}
