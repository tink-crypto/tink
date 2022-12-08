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

package awskms_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"flag"
	// context is used to cancel outstanding requests
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"

	"github.com/google/tink/go/integration/awskms"
)

const (
	keyAliasURI = "aws-kms://arn:aws:kms:us-east-2:235739564943:alias/unit-and-integration-testing"
	keyURI      = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	profile     = "tink-user1"
)

var (
	credFile    = "tink_go/testdata/aws/credentials.csv"
	credINIFile = "tink_go/testdata/aws/credentials.ini"
)

func init() {
	certPath := filepath.Join(os.Getenv("TEST_SRCDIR"), "tink_base/roots.pem")
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

func setupKMS(t *testing.T, cf string, uri string) {
	t.Helper()
	g, err := awskms.NewClientWithCredentials(uri, cf)
	if err != nil {
		t.Fatalf("error setting up aws client: %v", err)
	}
	// The registry will return the first KMS client that claims support for
	// the keyURI.  The tests re-use the same keyURI, so clear any clients
	// registered by earlier tests before registering the new client.
	registry.ClearKMSClients()
	registry.RegisterKMSClient(g)
}

func TestKMSEnvelopeAEADEncryptAndDecrypt(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}

	for _, file := range []string{credFile, credINIFile} {
		setupKMS(t, filepath.Join(srcDir, file), keyURI)
		dek := aead.AES128CTRHMACSHA256KeyTemplate()
		template, err := aead.CreateKMSEnvelopeAEADKeyTemplate(keyURI, dek)
		if err != nil {
			t.Fatalf("aead.CreateKMSEnvelopeAEADKeyTemplate() err = %v, want nil", err)
		}
		handle, err := keyset.NewHandle(template)
		if err != nil {
			t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
		}
		a, err := aead.New(handle)
		if err != nil {
			t.Fatalf("aead.New() err = %v, want nil", err)
		}
		for _, ad := range [][]byte{nil, random.GetRandomBytes(20)} {
			pt := random.GetRandomBytes(20)
			ct, err := a.Encrypt(pt, ad)
			if err != nil {
				t.Fatalf("a.Encrypt(pt, ad) err = %v, want nil", err)
			}
			dt, err := a.Decrypt(ct, ad)
			if err != nil {
				t.Fatalf("a.Decrypt(ct, ad) err = %v, want nil", err)
			}
			if !bytes.Equal(dt, pt) {
				t.Errorf("a.Decrypt() = %q, want %q", dt, pt)
			}
		}
	}
}
