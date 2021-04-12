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

package daead_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
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

	// TODO: save the keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	d, err := daead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this data needs to be encrypted")
	aad := []byte("this data needs to be authenticated, but not encrypted")
	ct1, err := d.EncryptDeterministically(msg, aad)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := d.DecryptDeterministically(ct1, aad)
	if err != nil {
		log.Fatal(err)
	}

	ct2, err := d.EncryptDeterministically(msg, aad)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(ct1, ct2) {
		log.Fatal("ct1 != ct2")
	}

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct1))
	fmt.Printf("Original  plaintext: %s\n", msg)
	fmt.Printf("Decrypted Plaintext: %s\n", pt)
}

func TestDeterministicAEADInit(t *testing.T) {
	// Check for AES-SIV key manager.
	_, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}
