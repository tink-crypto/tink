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

package gcpkms_test

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
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
)

const (
	keyURI = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
)

var (
	credFile = "tink_go/testdata/credential.json"
)

func init() {
	certPath := filepath.Join(os.Getenv("TEST_SRCDIR"), "tink_base/roots.pem")
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

func setupKMS(t *testing.T) {
	t.Helper()

	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}

	g, err := gcpkms.NewClientWithCredentials(keyURI, filepath.Join(srcDir, credFile))
	if err != nil {
		t.Errorf("error setting up gcp client: %v", err)
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
