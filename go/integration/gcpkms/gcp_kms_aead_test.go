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

package gcpkms

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"flag"
	// context is used to cancel outstanding requests
	// TEST_SRCDIR to read the roots.pem
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

const (
	keyURI = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
)

var (
	// lint placeholder header, please ignore
	credFile = os.Getenv("TEST_SRCDIR") + "/" + os.Getenv("TEST_WORKSPACE") + "/" + "testdata/credential.json"
	// lint placeholder footer, please ignore
)

// lint placeholder header, please ignore
func init() {
	certPath := os.Getenv("TEST_SRCDIR") + "/" + os.Getenv("TEST_WORKSPACE") + "/" + "roots.pem"
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

// lint placeholder footer, please ignore

func setupKMS(t *testing.T) {
	t.Helper()
	g, err := NewGCPClient(keyURI)
	if err != nil {
		t.Errorf("error setting up gcp client: %v", err)
	}
	gcpClient, err := g.LoadCredentials(credFile)
	if gcpClient == nil {
		t.Fatal("error initialising gcp client as it is nil")
	}
	if err != nil {
		t.Errorf("error loading credentials : %v", err)
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
	setupKMS(t)
	dek := aead.AES128CTRHMACSHA256KeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	if err != nil {
		t.Errorf("error getting a new keyset handle: %v", err)
	}
	a, err := aead.New(kh)
	if err != nil {
		t.Errorf("error getting the primitive: %v", err)
	}
	if err := basicAEADTest(t, a); err != nil {
		t.Errorf("error in basic aead tests: %v", err)
	}
}
