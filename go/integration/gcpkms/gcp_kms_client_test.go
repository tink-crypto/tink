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
//
////////////////////////////////////////////////////////////////////////////////

package gcpkms_test

import (
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
)

func Example() {
	const keyURI = "gcp-kms://......"

	gcpclient, err := gcpkms.NewClientWithCredentials(keyURI, "/mysecurestorage/credentials.json")
	if err != nil {
		log.Fatal(err)
	}
	registry.RegisterKMSClient(gcpclient)

	dek := aead.AES128CTRHMACSHA256KeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	if err != nil {
		log.Fatal(err)
	}
	a, err := aead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	ct, err := a.Encrypt([]byte("this data needs to be encrypted"), []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = a.Decrypt(ct, []byte("this data needs to be authenticated, but not encrypted"))
	if err != nil {
		log.Fatal(err)
	}
}
