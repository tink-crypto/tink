// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// //////////////////////////////////////////////////////////////////////////////
package hcvault_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/tink/go/integration/hcvault"
)

const (
	keyURITmpl = "hcvault://localhost:%d/transit/keys/key-1"
	token      = "mytoken"
)

var (
	vaultKey  = filepath.Join(os.Getenv("TEST_WORKSPACE"), "/integration/hcvault/testdata/server.key")
	vaultCert = filepath.Join(os.Getenv("TEST_WORKSPACE"), "/integration/hcvault/testdata/server.crt")
)

func TestVaultClientGetAEAD_EncryptDecrypt(t *testing.T) {
	port, stopFunc := newServer(t)
	defer stopFunc()

	client, err := hcvault.NewClient(
		fmt.Sprintf("hcvault://localhost:%d/", port),
		// Using InsecureSkipVerify is fine here, since this is just a test running locally.
		&tls.Config{InsecureSkipVerify: true}, // NOLINT
		token,
	)
	if err != nil {
		t.Fatal("Cannot initialize a client:", err)
	}

	keyURI := fmt.Sprintf(keyURITmpl, port)
	aead, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatal("Cannot obtain Vault AEAD:", err)
	}
	plaintext := []byte("plaintext")
	context := []byte("context")
	ciphertext, err := aead.Encrypt(plaintext, context)
	if err != nil {
		t.Fatal("Error encrypting data:", err)
	}
	gotPlaintext, err := aead.Decrypt(ciphertext, context)
	if err != nil {
		t.Fatal("Error decrypting data:", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("Incorrect plain text, want=%s;got=%s", string(plaintext), string(gotPlaintext))
	}

	invalidContext := []byte("invalidContext")
	_, err = aead.Decrypt(ciphertext, invalidContext)
	if err == nil {
		t.Error("aead.Decrypt(ciphertext, invalidContext) err = nil, want error")
	}
}

func TestVaultClientGetAEAD_DecryptWithFixedCiphertext(t *testing.T) {
	port, stopFunc := newServer(t)
	defer stopFunc()

	client, err := hcvault.NewClient(
		fmt.Sprintf("hcvault://localhost:%d/", port),
		// Using InsecureSkipVerify is fine here, since this is just a test running locally.
		&tls.Config{InsecureSkipVerify: true}, // NOLINT
		token,
	)
	if err != nil {
		t.Fatal("Cannot initialize a client:", err)
	}

	keyURI := fmt.Sprintf(keyURITmpl, port)
	aead, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatal("Cannot obtain Vault AEAD:", err)
	}
	// associatedData is passed as "context" parameter to vault decrypt.
	ciphertext := fakeEncrypt([]byte("plaintext"), nil, []byte("context"))
	context := []byte("context")
	plaintext, err := aead.Decrypt(ciphertext, context)
	if err != nil {
		t.Fatal("Error decrypting data:", err)
	}
	if !bytes.Equal(plaintext, []byte("plaintext")) {
		t.Fatalf("plaintext = %q, want \"plaintext\"", string(plaintext))
	}
}

func TestGetAEADFailWithBadKeyURI(t *testing.T) {
	port, stopFunc := newServer(t)
	defer stopFunc()

	client, err := hcvault.NewClient(
		fmt.Sprintf("hcvault://localhost:%d/", port),
		// Using InsecureSkipVerify is fine here, since this is just a test running locally.
		&tls.Config{InsecureSkipVerify: true}, // NOLINT
		token,
	)
	if err != nil {
		t.Fatalf("hcvault.NewClient() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name   string
		keyURI string
	}{
		{
			name:   "empty",
			keyURI: fmt.Sprintf("hcvault://localhost:%d/", port),
		},
		{
			name:   "without slash",
			keyURI: fmt.Sprintf("hcvault://localhost:%d/badKeyUri", port),
		},
		{
			name:   "with one slash",
			keyURI: fmt.Sprintf("hcvault://localhost:%d/bad/KeyUri", port),
		},
		{
			name:   "with three slash",
			keyURI: fmt.Sprintf("hcvault://localhost:%d/one/two/three/four", port),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.GetAEAD(test.keyURI); err == nil {
				t.Errorf("client.GetAEAD(%q) err = nil, want error", test.keyURI)
			}
		})
	}
}

type closeFunc func() error

func newServer(t *testing.T) (int, closeFunc) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {

		// Encrypt
		case "/v1/transit/encrypt/key-1":
			decoder := json.NewDecoder(r.Body)
			var encReq = make(map[string]string)
			if err := decoder.Decode(&encReq); err != nil {
				http.Error(w, fmt.Sprintf("Cannot decode encryption request: %s", err), 400)
				return
			}
			plaintext, err := base64.StdEncoding.DecodeString(encReq["plaintext"])
			if err != nil {
				http.Error(w, "Plaintext must be base64 encoded", 400)
				return
			}
			context, err := base64.StdEncoding.DecodeString(encReq["context"])
			if err != nil {
				http.Error(w, "context must be base64 encoded", 400)
				return
			}
			associatedData, err := base64.StdEncoding.DecodeString(encReq["associated_data"])
			if err != nil {
				http.Error(w, "associated_data must be base64 encoded", 400)
				return
			}
			ciphertext := fakeEncrypt(plaintext, associatedData, context)
			resp := map[string]any{
				"data": map[string]string{
					"ciphertext": string(ciphertext),
				},
			}
			respBytes, err := json.Marshal(resp)
			if err != nil {
				t.Fatal("Cannot encode encrypted data:", err)
			}
			if _, err := w.Write(respBytes); err != nil {
				t.Fatal("Cannot send encrypted data response:", err)
			}

		// Decrypt
		case "/v1/transit/decrypt/key-1":
			decoder := json.NewDecoder(r.Body)
			var decReq = make(map[string]string)
			if err := decoder.Decode(&decReq); err != nil {
				http.Error(w, fmt.Sprintf("Cannot decode decryption request: %s", err), 400)
				return
			}
			ciphertext := []byte(decReq["ciphertext"])
			context, err := base64.StdEncoding.DecodeString(decReq["context"])
			if err != nil {
				http.Error(w, "context must be base64 encoded", 400)
				return
			}
			associatedData, err := base64.StdEncoding.DecodeString(decReq["associated_data"])
			if err != nil {
				http.Error(w, "associated_data must be base64 encoded", 400)
				return
			}
			plaintext, err := fakeDecrypt(ciphertext, associatedData, context)
			if err != nil {
				http.Error(w, fmt.Sprintf("Cannot decrypt ciphertext: %s", err), 400)
				return
			}
			resp := map[string]any{
				"data": map[string]string{
					"plaintext": base64.StdEncoding.EncodeToString(plaintext),
				},
			}
			respBytes, err := json.Marshal(resp)
			if err != nil {
				t.Fatal("Cannot encode encrypted data:", err)
			}
			if _, err := w.Write(respBytes); err != nil {
				t.Fatal("Cannot send encrypted data response:", err)
			}

		default:
			http.NotFound(w, r)
		}
	}

	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}

	vaultCertPath := filepath.Join(srcDir, vaultCert)
	if _, err := os.Stat(vaultCertPath); err != nil {
		t.Fatal("Cannot load Vault certificate file:", err)
	}
	vaultKeyPath := filepath.Join(srcDir, vaultKey)
	if _, err := os.Stat(vaultKeyPath); err != nil {
		t.Fatal("Cannot load Vault key file:", err)
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("Cannot start Vault mock server:", err)
	}
	go http.ServeTLS(l, http.HandlerFunc(handler), vaultCertPath, vaultKeyPath)

	port := l.Addr().(*net.TCPAddr).Port
	return port, l.Close
}

// The ciphertext returned by HC Vault is of the form:
//
//   vault:v1:<ciphertext>
//
// where ciphertext is base64-encoded. See:
// https://developer.hashicorp.com/vault/api-docs/secret/transit#sample-request-13
//
// The ciphertext returned by this fake implementation is of the form:
//
//   enc:<context>:<associatedData>:<plaintext>
//
// where context, associatedData and plaintext are base64-encoded.
// It is deterministic and not secure.
func fakeEncrypt(plaintext, associatedData, context []byte) []byte {
	s := fmt.Sprintf(
		"enc:%s:%s:%s",
		base64.StdEncoding.EncodeToString(context),
		base64.StdEncoding.EncodeToString(associatedData),
		base64.StdEncoding.EncodeToString(plaintext),
	)
	return []byte(s)
}

func TestFakeEncrypt(t *testing.T) {
	want := []byte("enc:Y29udGV4dA==:YXNzb2NpYXRlZERhdGE=:cGxhaW50ZXh0")
	got := fakeEncrypt([]byte("plaintext"), []byte("associatedData"), []byte("context"))
	if !bytes.Equal(got, want) {
		t.Errorf("got = %q, want %q", string(got), string(want))
	}
}

func TestFakeEncryptWithoutAssociatedData(t *testing.T) {
	want := []byte("enc:Y29udGV4dA==::cGxhaW50ZXh0")
	got := fakeEncrypt([]byte("plaintext"), nil, []byte("context"))
	if !bytes.Equal(got, want) {
		t.Errorf("got = %q, want %q", string(got), string(want))
	}
}

func TestFakeEncryptWithoutContext(t *testing.T) {
	want := []byte("enc::YXNzb2NpYXRlZERhdGE=:cGxhaW50ZXh0")
	got := fakeEncrypt([]byte("plaintext"), []byte("associatedData"), nil)
	if !bytes.Equal(got, want) {
		t.Errorf("got = %q, want %q", string(got), string(want))
	}
}

func fakeDecrypt(ciphertext, associatedData, context []byte) ([]byte, error) {
	ct := string(ciphertext)
	parts := strings.Split(ct, ":")
	if len(parts) != 4 || parts[0] != "enc" {
		return nil, fmt.Errorf("malformed ciphertext: %s", ciphertext)
	}
	context2, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(context, context2) {
		return nil, fmt.Errorf("invalid context: %s != %s", context2, context)
	}
	associatedData2, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(associatedData2, associatedData) {
		return nil, fmt.Errorf("invalid associatedData: %s != %s", associatedData2, associatedData)
	}
	plaintext, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func TestFakeEncryptDecrypt(t *testing.T) {
	ciphertext := fakeEncrypt([]byte("plaintext"), []byte("associatedData"), []byte("context"))
	got, err := fakeDecrypt(ciphertext, []byte("associatedData"), []byte("context"))
	if err != nil {
		t.Errorf("fakeDecrypt() err = %s, want nil", err)
	}
	if want := []byte("plaintext"); !bytes.Equal(got, want) {
		t.Errorf("fakeDecrypt() = %q, want %q", string(got), string(want))
	}
}
