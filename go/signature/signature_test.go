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

package signature_test

// [START signature-example]

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
)

func Example() {
	// A private keyset created with
	// "tinkey create-keyset --key-template=ECDSA_P256 --out private_keyset.cfg".
	// Note that this keyset has the secret key information in cleartext.
	privateJSONKeyset := `{
		"key": [{
			"keyData": {
					"keyMaterialType":
							"ASYMMETRIC_PRIVATE",
					"typeUrl":
							"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
					"value":
							"EkwSBggDEAIYAhogEiSZ9u2nDtvZuDgWgGsVTIZ5/V08N4ycUspTX0RYRrkiIHpEwHxQd1bImkyMvV2bqtUbgMh5uPSTdnUEGrPXdt56GiEA3iUi+CRN71qy0fOCK66xAW/IvFyjOGtxjppRhSFUneo="
			},
			"keyId": 611814836,
			"outputPrefixType": "TINK",
			"status": "ENABLED"
		}],
		"primaryKeyId": 611814836
	}`

	// The corresponding public keyset created with
	// "tinkey create-public-keyset --in private_keyset.cfg"
	publicJSONKeyset := `{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "ASYMMETRIC_PUBLIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
              "value":
                  "EgYIAxACGAIaIBIkmfbtpw7b2bg4FoBrFUyGef1dPDeMnFLKU19EWEa5IiB6RMB8UHdWyJpMjL1dm6rVG4DIebj0k3Z1BBqz13beeg=="
          },
          "keyId": 611814836,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 611814836
  }`

	// Create a keyset handle from the cleartext private keyset in the previous
	// step. The keyset handle provides abstract access to the underlying keyset to
	// limit the access of the raw key material. WARNING: In practice,
	// it is unlikely you will want to use a insecurecleartextkeyset, as it implies
	// that your key material is passed in cleartext, which is a security risk.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.
	privateKeysetHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBufferString(privateJSONKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the Signer primitive from privateKeysetHandle.
	signer, err := signature.NewSigner(privateKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive to sign a message. In this case, the primary key of the
	// keyset will be used (which is also the only key in this example).
	data := []byte("data")
	sig, err := signer.Sign(data)
	if err != nil {
		log.Fatal(err)
	}

	// Create a keyset handle from the keyset containing the public key. Because the
	// public keyset does not contain any secrets, we can use [keyset.ReadWithNoSecrets].
	publicKeysetHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewJSONReader(bytes.NewBufferString(publicJSONKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the Verifier primitive from publicKeysetHandle.
	verifier, err := signature.NewVerifier(publicKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	if err = verifier.Verify(sig, data); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("sig is valid")
	// Output: sig is valid
}

// [END signature-example]
