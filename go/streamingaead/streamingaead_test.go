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

package streamingaead_test

// [START streaming-aead-example]

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
)

func Example() {
	// A keyset created with "tinkey create-keyset --key-template=AES256_CTR_HMAC_SHA256_1MB". Note
	// that this keyset has the secret key information in cleartext.
	jsonKeyset := `{
    "primaryKeyId": 1720777699,
    "key": [{
        "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey",
            "keyMaterialType": "SYMMETRIC",
            "value": "Eg0IgCAQIBgDIgQIAxAgGiDtesd/4gCnQdTrh+AXodwpm2b6BFJkp043n+8mqx0YGw=="
        },
        "outputPrefixType": "RAW",
        "keyId": 1720777699,
        "status": "ENABLED"
    }]
	}`

	// Create a keyset handle from the cleartext keyset in the previous
	// step. The keyset handle provides abstract access to the underlying keyset to
	// limit the exposure of accessing the raw key material. WARNING: In practice,
	// it is unlikely you will want to use an insecurecleartextkeyset, as it implies
	// that your key material is passed in cleartext, which is a security risk.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.
	keysetHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the StreamingAEAD primitive we want to use from the keyset handle.
	primitive, err := streamingaead.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Create a file with the plaintext.
	dir, err := os.MkdirTemp("", "streamingaead")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	plaintextPath := filepath.Join(dir, "plaintext")
	if err := os.WriteFile(plaintextPath, []byte("this data needs to be encrypted"), 0666); err != nil {
		log.Fatal(err)
	}
	plaintextFile, err := os.Open(plaintextPath)
	if err != nil {
		log.Fatal(err)
	}

	// associatedData defines the context of the encryption. Here, we include the path of the
	// plaintext file.
	associatedData := []byte("associatedData for " + plaintextPath)

	// Encrypt the plaintext file and write the output to the ciphertext file. In this case the
	// primary key of the keyset will be used (which is also the only key in this example).
	ciphertextPath := filepath.Join(dir, "ciphertext")
	ciphertextFile, err := os.Create(ciphertextPath)
	if err != nil {
		log.Fatal(err)
	}
	w, err := primitive.NewEncryptingWriter(ciphertextFile, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(w, plaintextFile); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	if err := ciphertextFile.Close(); err != nil {
		log.Fatal(err)
	}
	if err := plaintextFile.Close(); err != nil {
		log.Fatal(err)
	}

	// Decrypt the ciphertext file and write the output to the decrypted file. The
	// decryption finds the correct key in the keyset and decrypts the ciphertext.
	// If no key is found or decryption fails, it returns an error.
	ciphertextFile, err = os.Open(ciphertextPath)
	if err != nil {
		log.Fatal(err)
	}
	decryptedPath := filepath.Join(dir, "decrypted")
	decryptedFile, err := os.Create(decryptedPath)
	if err != nil {
		log.Fatal(err)
	}
	r, err := primitive.NewDecryptingReader(ciphertextFile, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(decryptedFile, r); err != nil {
		log.Fatal(err)
	}
	if err := decryptedFile.Close(); err != nil {
		log.Fatal(err)
	}
	if err := ciphertextFile.Close(); err != nil {
		log.Fatal(err)
	}

	// Print the content of the decrypted file.
	b, err := os.ReadFile(decryptedPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
	// Output: this data needs to be encrypted
}

// [END streaming-aead-example]
