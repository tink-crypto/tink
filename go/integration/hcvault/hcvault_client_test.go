// Copyright 2019 Google Inc.
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

package hcvault_test

import (
	"crypto/tls"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/integration/hcvault"
)

func Example() {
	// Use a key with key derivation enabled (with "derived=true") if you use a non-empty
	// associated_data.
	const keyURI = "hcvault://hcvault.corp.com:8200/transit/keys/key-1"

	vaultClient, err := hcvault.NewClient(keyURI, tlsConfig(), vaultToken())
	if err != nil {
		log.Fatal(err)
	}
	kekAEAD, err := vaultClient.GetAEAD(keyURI)
	if err != nil {
		log.Fatal(err)
	}
	dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	a := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")

	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}

	_, err = a.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
}

func tlsConfig() *tls.Config {
	// Return a TLS configuration used to communicate with Vault server via HTTPS.
	return nil
}

func vaultToken() string {
	return "" // Your Vault token.
}
