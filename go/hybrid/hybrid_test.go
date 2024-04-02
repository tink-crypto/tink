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

package hybrid_test

// [START hybrid-example]

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func Example() {
	// A private keyset created with
	// "tinkey create-keyset --key-template=DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM --out private_keyset.cfg".
	// Note that this keyset has the secret key information in cleartext.
	privateJSONKeyset := `{
		"key": [{
				"keyData": {
						"keyMaterialType":
								"ASYMMETRIC_PRIVATE",
						"typeUrl":
								"type.googleapis.com/google.crypto.tink.HpkePrivateKey",
						"value":
								"EioSBggBEAEYAhogVWQpmQoz74jcAp5WOD36KiBQ71MVCpn2iWfOzWLtKV4aINfn8qlMbyijNJcCzrafjsgJ493ZZGN256KTfKw0WN+p"
				},
				"keyId": 958452012,
				"outputPrefixType": "TINK",
				"status": "ENABLED"
		}],
		"primaryKeyId": 958452012
  }`

	// The corresponding public keyset created with
	// "tinkey create-public-keyset --in private_keyset.cfg".
	publicJSONKeyset := `{
		"key": [{
				"keyData": {
						"keyMaterialType":
								"ASYMMETRIC_PUBLIC",
						"typeUrl":
								"type.googleapis.com/google.crypto.tink.HpkePublicKey",
						"value":
								"EgYIARABGAIaIFVkKZkKM++I3AKeVjg9+iogUO9TFQqZ9olnzs1i7Sle"
				},
				"keyId": 958452012,
				"outputPrefixType": "TINK",
				"status": "ENABLED"
		}],
		"primaryKeyId": 958452012
  }`

	// Create a keyset handle from the keyset containing the public key. Because the
	// public keyset does not contain any secrets, we can use [keyset.ReadWithNoSecrets].
	publicKeysetHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewJSONReader(bytes.NewBufferString(publicJSONKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the HybridEncrypt primitive from publicKeysetHandle.
	encPrimitive, err := hybrid.NewHybridEncrypt(publicKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("message")
	encryptionContext := []byte("encryption context")
	ciphertext, err := encPrimitive.Encrypt(plaintext, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

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

	// Retrieve the HybridDecrypt primitive from privateKeysetHandle.
	decPrimitive, err := hybrid.NewHybridDecrypt(privateKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := decPrimitive.Decrypt(ciphertext, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypted))
	// Output: message
}
// [END hybrid-example]
