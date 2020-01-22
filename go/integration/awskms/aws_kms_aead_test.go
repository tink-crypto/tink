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
	// ignore-placeholder1
	// ignore-placeholder2
	"testing"

	"flag"
	// context is used to cancel outstanding requests
	// TEST_SRCDIR to read the roots.pem
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	// ignore-placeholder3
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

const (
	keyURI  = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	profile = "tink-user1"
)

var (
	// lint placeholder header, please ignore
	credFile    = os.Getenv("TEST_SRCDIR") + "/tink_base/testdata/credentials_aws.csv"
	badCredFile = os.Getenv("TEST_SRCDIR") + "/tink_base/testdata/bad_access_keys_aws.csv"
	credINIFile = os.Getenv("TEST_SRCDIR") + "/tink_base/testdata/credentials_aws.cred"
	// lint placeholder footer, please ignore
)

// lint placeholder header, please ignore
func init() {
	certPath := os.Getenv("TEST_SRCDIR") + "/" + os.Getenv("TEST_WORKSPACE") + "/" + "roots.pem"
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

// lint placeholder footer, please ignore

func setupKMS(t *testing.T, cf string) {
	t.Helper()
	g, err := NewClientWithCredentials(keyURI, cf)
	if err != nil {
		t.Fatalf("error setting up aws client: %v", err)
	}
	registry.RegisterKMSClient(g)
}

func basicAEADTest(t *testing.T, a tink.AEAD) error {
	t.Helper()
	for i := 0; i < 100; i++ {
		pt := random.GetRandomBytes(20)
		ad := random.GetRandomBytes(20)
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
	for _, file := range []string{credFile, credINIFile} {
		setupKMS(t, file)
		// ignore-placeholder4
		dek := aead.AES128CTRHMACSHA256KeyTemplate()
		kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
		if err != nil {
			t.Fatalf("error getting a new keyset handle: %v", err)
		}
		a, err := awsaead(kh)
		if err != nil {
			t.Fatalf("error getting the primitive: %v", err)
		}
		if err := basicAEADTest(t, a); err != nil {
			t.Errorf("error in basic aead tests: %v", err)
		}
	}
}

func TestBasicAeadWithoutAdditionalData(t *testing.T) {
	for _, file := range []string{credFile, credINIFile} {
		setupKMS(t, file)
		// ignore-placeholder4
		dek := aead.AES128CTRHMACSHA256KeyTemplate()
		kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
		if err != nil {
			t.Fatalf("error getting a new keyset handle: %v", err)
		}
		a, err := awsaead(kh)
		if err != nil {
			t.Fatalf("error getting the primitive: %v", err)
		}
		for i := 0; i < 100; i++ {
			pt := random.GetRandomBytes(20)
			ct, err := a.Encrypt(pt, nil)
			if err != nil {
				t.Fatalf("error encrypting data: %v", err)
			}
			dt, err := a.Decrypt(ct, nil)
			if err != nil {
				t.Fatalf("error decrypting data: %v", err)
			}
			if !bytes.Equal(dt, pt) {
				t.Fatalf("decrypt not inverse of encrypt")
			}
		}
	}
}

// ignore-placeholder5

func TestLoadBadCSVCredential(t *testing.T) {
	_, err := NewClientWithCredentials(keyURI, badCredFile)
	if err == nil {
		t.Fatalf("does not reject two-column csv file, expect error : %v", errCredCSV)
	}
	if err != errCredCSV {
		t.Fatalf("expect error : %v, got: %v", errCredCSV, err)
	}
}
