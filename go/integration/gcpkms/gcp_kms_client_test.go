// Copyright 2017 Google Inc.
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

package gcpkms_test

import (
	"context"
	"log"

	"google.golang.org/api/option"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/integration/gcpkms"
)

func Example() {
	const keyURI = "gcp-kms://......"
	ctx := context.Background()
	gcpclient, err := gcpkms.NewClientWithOptions(ctx, keyURI, option.WithCredentialsFile("/mysecurestorage/credentials.json"))
	if err != nil {
		log.Fatal(err)
	}
	kekAEAD, err := gcpclient.GetAEAD(keyURI)
	if err != nil {
		log.Fatal(err)
	}

	// Get the KMS envelope AEAD primitive.
	dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	primitive := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive.
	plaintext := []byte("message")
	associatedData := []byte("example KMS envelope AEAD encryption")

	ciphertext, err := primitive.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}

	_, err = primitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
}
