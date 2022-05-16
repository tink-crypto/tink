// Copyright 2017 Google LLC
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

package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"flag"
	// context is used to cancel outstanding requests
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	gcpURI      = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
	gcpCredFile = filepath.Join(os.Getenv("TEST_SRCDIR"), "tools/testdata/credential.json")
	awsURI      = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	awsCredFile = filepath.Join(os.Getenv("TEST_SRCDIR"), "tools/testdata/credentials_aws.csv")
)

func init() {
	certPath := path.Join(os.Getenv("TEST_SRCDIR"), "tink_base/roots.pem")
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s keyset-file kms dek-template", os.Args[0])
	}
	f := os.Args[1]
	kms := os.Args[2]
	dek := os.Args[3]
	var dekT *tinkpb.KeyTemplate
	var kh *keyset.Handle
	var b bytes.Buffer
	switch strings.ToUpper(dek) {
	case "AES128_GCM":
		dekT = aead.AES128GCMKeyTemplate()
	case "AES128_CTR_HMAC_SHA256":
		dekT = aead.AES128CTRHMACSHA256KeyTemplate()
	default:
		log.Fatalf("DEK template %s, is not supported. Expecting AES128_GCM or AES128_CTR_HMAC_SHA256", dek)
	}
	switch strings.ToUpper(kms) {
	case "GCP":
		gcpclient, err := gcpkms.NewClientWithCredentials(gcpURI, gcpCredFile)
		if err != nil {
			log.Fatal(err)
		}
		registry.RegisterKMSClient(gcpclient)
		kh, err = keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(gcpURI, dekT))
		if err != nil {
			log.Fatal(err)
		}
	case "AWS":
		awsclient, err := awskms.NewClientWithCredentials(awsURI, awsCredFile)
		if err != nil {
			log.Fatal(err)
		}
		registry.RegisterKMSClient(awsclient)
		kh, err = keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(awsURI, dekT))
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("KMS %s, is not supported. Expecting AWS or GCP", kms)
	}
	ks := insecurecleartextkeyset.KeysetMaterial(kh)
	h, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}
	if err := insecurecleartextkeyset.Write(h, keyset.NewBinaryWriter(&b)); err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(f, b.Bytes(), 0644); err != nil {
		log.Fatal(err)
	}
}
