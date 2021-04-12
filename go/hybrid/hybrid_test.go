// Copyright 2020 Google LLC
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
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
)

func Example() {
	khPriv, err := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	// TODO: save the private keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	khPub, err := khPriv.Public()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: share the public keyset with the sender.

	enc, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this data needs to be encrypted")
	encryptionContext := []byte("encryption context")
	ct, err := enc.Encrypt(msg, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	dec, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := dec.Decrypt(ct, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct))
	fmt.Printf("Original  plaintext: %s\n", msg)
	fmt.Printf("Decrypted Plaintext: %s\n", pt)
}
