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

package awskms

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"flag"
	// context is used to cancel outstanding requests
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

const (
	keyAliasURI = "aws-kms://arn:aws:kms:us-east-2:235739564943:alias/unit-and-integration-testing"
	keyURI      = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	profile     = "tink-user1"
)

var (
	credFile    = "tink_base/testdata/credentials_aws.csv"
	credINIFile = "tink_base/testdata/credentials_aws.ini"
)

func init() {
	certPath := filepath.Join(os.Getenv("TEST_SRCDIR"), "tink_base/roots.pem")
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

func setupKMS(t *testing.T, cf string) {
	t.Helper()
	setupKMSWithURI(t, cf, keyURI)
}

func setupKMSWithURI(t *testing.T, cf string, uri string) {
	t.Helper()
	g, err := NewClientWithCredentials(uri, cf)
	if err != nil {
		t.Fatalf("error setting up aws client: %v", err)
	}
	// The registry will return the first KMS client that claims support for
	// the keyURI.  The tests re-use the same keyURI, so clear any clients
	// registered by earlier tests before registering the new client.
	registry.ClearKMSClients()
	registry.RegisterKMSClient(g)
}

func basicAEADTest(t *testing.T, a tink.AEAD) error {
	t.Helper()
	return basicAEADTestWithOptions(t, a, 100 /*loopCount*/, true /*withAdditionalData*/)
}

func basicAEADTestWithOptions(t *testing.T, a tink.AEAD, loopCount int, withAdditionalData bool) error {
	t.Helper()
	for i := 0; i < loopCount; i++ {
		pt := random.GetRandomBytes(20)
		var ad []byte = nil
		if withAdditionalData {
			ad = random.GetRandomBytes(20)
		}
		ct, err := a.Encrypt(pt, ad)
		if err != nil {
			return err
		}
		dt, err := a.Decrypt(ct, ad)
		if err != nil {
			return err
		}
		if !bytes.Equal(dt, pt) {
			return errors.New("decrypt not inverse of encrypt")
		}
	}
	return nil
}

func TestBasicAead(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}

	for _, file := range []string{credFile, credINIFile} {
		setupKMS(t, filepath.Join(srcDir, file))
		dek := aead.AES128CTRHMACSHA256KeyTemplate()
		kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
		if err != nil {
			t.Fatalf("error getting a new keyset handle: %v", err)
		}
		a, err := aead.New(kh)
		if err != nil {
			t.Fatalf("error getting the primitive: %v", err)
		}
		if err := basicAEADTest(t, a); err != nil {
			t.Errorf("error in basic aead tests: %v", err)
		}
	}
}

func TestBasicAeadWithoutAdditionalData(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}

	for _, uri := range []string{keyURI, keyAliasURI} {
		for _, file := range []string{credFile, credINIFile} {
			setupKMSWithURI(t, filepath.Join(srcDir, file), uri)
			dek := aead.AES128CTRHMACSHA256KeyTemplate()
			kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(uri, dek))
			if err != nil {
				t.Fatalf("error getting a new keyset handle: %v", err)
			}
			a, err := aead.New(kh)
			if err != nil {
				t.Fatalf("error getting the primitive: %v", err)
			}
			// Only test 10 times (instead of 100) because each test makes HTTP requests to AWS.
			if err := basicAEADTestWithOptions(t, a, 10 /*loopCount*/, false /*withAdditionalData*/); err != nil {
				t.Errorf("error in basic aead tests without additinal data: %v", err)
			}
		}
	}
}
