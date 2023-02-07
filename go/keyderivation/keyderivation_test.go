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

package keyderivation_test

import (
	"fmt"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyderivation"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/prf"
)

func Example() {
	template, err := keyderivation.CreatePRFBasedKeyTemplate(prf.HKDFSHA256PRFKeyTemplate(), aead.AES128GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	handle, err := keyset.NewHandle(template)
	if err != nil {
		log.Fatal(err)
	}

	deriver, err := keyderivation.New(handle)
	if err != nil {
		log.Fatal(err)
	}

	derivedHandle, err := deriver.DeriveKeyset([]byte("salt"))
	if err != nil {
		log.Fatal(err)
	}

	// Use the derived keyset.
	a, err := aead.New(derivedHandle)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := a.Encrypt([]byte("a secret message"), nil)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := a.Decrypt(ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext))
	// Output: a secret message
}
