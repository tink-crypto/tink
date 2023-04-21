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

package mac_test

// [START mac-example]

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
)

func Example() {
	// A keyset created with "tinkey create-keyset --key-template=HMAC_SHA256_128BITTAG".
	// Note that this keyset has the secret key information in cleartext.
	jsonKeyset := `{
			"key": [{
					"keyData": {
							"keyMaterialType":
									"SYMMETRIC",
							"typeUrl":
									"type.googleapis.com/google.crypto.tink.HmacKey",
							"value":
									"EgQIAxAQGiA0LQjovcydWhVQV3k8W9ZSRkd7Ei4Y/TRWApE8guwV4Q=="
					},
					"keyId": 1892702217,
					"outputPrefixType": "TINK",
					"status": "ENABLED"
			}],
			"primaryKeyId": 1892702217
	}`

	// Create a keyset handle from the cleartext keyset in the previous
	// step. The keyset handle provides abstract access to the underlying keyset to
	// limit the exposure of accessing the raw key material. WARNING: In practice,
	// it is unlikely you will want to use a insecurecleartextkeyset, as it implies
	// that your key material is passed in cleartext, which is a security risk.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.
	keysetHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the MAC primitive we want to use from the keyset handle.
	primitive, err := mac.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive to create a MAC tag for some data. In this case the primary
	// key of the keyset will be used (which is also the only key in this example).
	data := []byte("data")
	tag, err := primitive.ComputeMAC(data)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive to verify the tag. VerifyMAC finds the correct key in
	// the keyset. If no key is found or verification fails, it returns an error.
	err = primitive.VerifyMAC(tag, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("tag is valid")
	// Output: tag is valid
}

// [END mac-example]
