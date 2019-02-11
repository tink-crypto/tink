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

	"google3/base/go/flag"
	"google3/base/go/google"
	"google3/base/go/runfiles"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/registry"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

const (
	credFile = "testdata/credential.json"
	keyURI   = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
)

func init() {
	google.RegisterInit(func() {
		certPath := runfiles.Path("google3/security/cacerts/for_connecting_to_google/roots.pem")
		flag.Set("cacerts", certPath)
		os.Setenv("SSL_CERT_FILE", certPath)
	})
}
func setupKMS(t *testing.T) {
	t.Helper()
	g, err := NewGCPClient(keyURI)
	if err != nil {
		t.Errorf("error setting up gcp client: %v", err)
	}
	_, err = g.LoadCredentials(credFile)
	if err != nil {
		t.Errorf("error loading credentials : %v", err)
	}
	registry.RegisterKMSClient(g)
}

func basicAeadTest(t *testing.T, a tink.AEAD) error {
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
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAeadKeyTemplate(keyURI, dek))
	if err != nil {
		t.Errorf("error getting a new keyset handle: %v", err)
	}
	a, err := aead.New(kh)
	if err != nil {
		t.Errorf("error getting the primitive: %v", err)
	}
	if err := basicAeadTest(t, a); err != nil {
		t.Errorf("error in basic aead tests: %v", err)
	}
}
