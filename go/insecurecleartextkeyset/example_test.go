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

package insecurecleartextkeyset_test

// [START cleartext-keyset-example]

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func Example_cleartextKeysetInBinary() {
	// Generate a new keyset handle for the primitive we want to use.
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	// Serialize the keyset.
	buff := &bytes.Buffer{}
	err = insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		log.Fatal(err)
	}
	serializedKeyset := buff.Bytes()

	// serializedKeyset can now be stored at a secure location.
	// WARNING: Storing the keyset in cleartext to disk is not recommended!

	// Parse the keyset.
	parsedHandle, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Get the primitive.
	primitive, err := aead.New(parsedHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive.
	plaintext := []byte("message")
	associatedData := []byte("example encryption")
	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(decrypted))
	// Output: message
}

// [END cleartext-keyset-example]

func Example_cleartextKeysetInJSON() {
	// Generate a new keyset handle for the primitive we want to use.
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	// Serialize the keyset.
	buff := &bytes.Buffer{}
	err = insecurecleartextkeyset.Write(handle, keyset.NewJSONWriter(buff))
	if err != nil {
		log.Fatal(err)
	}
	serializedKeyset := buff.Bytes()

	// serializedKeyset can now be stored at a secure location.
	// WARNING: Storing the keyset in cleartext to disk is not recommended!

	// Parse the keyset.
	parsedHandle, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewBuffer(serializedKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Get the primitive.
	primitive, err := aead.New(parsedHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive.
	plaintext := []byte("message")
	associatedData := []byte("example encryption")
	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(decrypted))
	// Output: message
}
