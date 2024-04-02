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

package gcpkms_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"flag"
	// context is used to cancel outstanding requests
	"google.golang.org/api/option"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/integration/gcpkms"
)

const (
	keyURI = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
)

var (
	credFile = "testdata/gcp/credential.json"
)

func init() {
	certPath := filepath.Join(os.Getenv("TEST_SRCDIR"), "tink_base/roots.pem")
	flag.Set("cacerts", certPath)
	os.Setenv("SSL_CERT_FILE", certPath)
}

func TestGetAeadWithEnvelopeAead(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	workspaceDir, ok := os.LookupEnv("TEST_WORKSPACE")
	if !ok {
		t.Skip("TEST_WORKSPACE not set")
	}
	ctx := context.Background()
	gcpClient, err := gcpkms.NewClientWithOptions(
		ctx, keyURI, option.WithCredentialsFile(filepath.Join(srcDir, workspaceDir, credFile)))
	if err != nil {
		t.Fatalf("gcpkms.NewClientWithOptions() err = %q, want nil", err)
	}
	kekAEAD, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("gcpClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	a := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
	}
	plaintext := []byte("message")
	associatedData := []byte("example KMS envelope AEAD encryption")

	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
	}
	gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}

	_, err = a.Decrypt(ciphertext, []byte("invalid associatedData"))
	if err == nil {
		t.Error("a.Decrypt(ciphertext, []byte(\"invalid associatedData\")) err = nil, want error")
	}
}
