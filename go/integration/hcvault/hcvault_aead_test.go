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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vault_api "github.com/hashicorp/vault/api"
	"github.com/google/tink/go/integration/hcvault"
)

const (
	keyURITmpl = "%s/transit/keys/key-1"
	token      = "mytoken"
)

func TestVaultNewAEAD_EncryptDecrypt(t *testing.T) {
	server, _, tlsConfig := newServer(t)
	defer server.Close()

	client := newVaultAPIClient(t, server.URL, token, tlsConfig)

	aead, err := hcvault.NewAEAD("/transit/keys/key-1", client.Logical())
	if err != nil {
		t.Fatalf("hcvault.NewAEAD() err = %v, want nil", err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := aead.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aead.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	gotPlaintext, err := aead.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("aead.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("aead.Decrypt(ciphertext, associatedData) = %s, want %s", gotPlaintext, plaintext)
	}

	otherAssociatedData := []byte("otherAssociatedData")
	_, err = aead.Decrypt(ciphertext, otherAssociatedData)
	if err == nil {
		t.Error("aead.Decrypt(ciphertext, otherAssociatedData) err = nil, want error")
	}
}

func TestVaultNewAEAD_DecryptWithFixedCiphertext(t *testing.T) {
	server, _, tlsConfig := newServer(t)
	defer server.Close()

	client := newVaultAPIClient(t, server.URL, token, tlsConfig)

	aead, err := hcvault.NewAEAD("/transit/keys/key-1", client.Logical())
	if err != nil {
		t.Fatalf("hcvault.NewAEAD() err = %v, want nil", err)
	}

	// associatedData is passed as "context" parameter to vault decrypt.
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext := fakeEncrypt(plaintext, associatedData, nil)

	gotPlaintext, err := aead.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("aead.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("aead.Decrypt(ciphertext, associatedData) = %s, want %s", gotPlaintext, associatedData)
	}
}

func TestVaultNewAEADWithLegacyContextParamater_isCompatible(t *testing.T) {
	server, uriPrefix, tlsConfig := newServer(t)
	defer server.Close()

	client := newVaultAPIClient(t, server.URL, token, tlsConfig)

	// Create AEAD with WithLegacyContextParamater.
	aead1, err := hcvault.NewAEAD("/transit/keys/key-1", client.Logical(), hcvault.WithLegacyContextParamater())
	if err != nil {
		t.Fatalf("hcvault.NewAEAD() err = %v, want nil", err)
	}

	// Create AEAD with hcvault.NewClient and GetAEAD.
	hcvaultClient, err := hcvault.NewClient(uriPrefix, tlsConfig, token)
	if err != nil {
		t.Fatalf("hcvault.NewClient() err = %v, want nil", err)
	}
	keyURI := fmt.Sprintf("%s/transit/keys/key-1", uriPrefix)
	aead2, err := hcvaultClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("hcvaultClient.GetAEAD(%q) err = %v, want nil", keyURI, err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext2, err := aead2.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aead2.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	gotPlaintext1, err := aead1.Decrypt(ciphertext2, associatedData)
	if err != nil {
		t.Fatalf("aead1.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext1, plaintext) {
		t.Fatalf("aead1.Decrypt(ciphertext2, associatedData) = %s, want %s", gotPlaintext1, plaintext)
	}

	ciphertext1, err := aead1.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aead2.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	gotPlaintext2, err := aead2.Decrypt(ciphertext1, associatedData)
	if err != nil {
		t.Fatalf("aead2.Decrypt(ciphertext1, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext2, plaintext) {
		t.Fatalf("aead2.Decrypt(ciphertext1, associatedData) = %s, want %s", gotPlaintext2, plaintext)
	}
}

func TestVaultClientAEAD_EncryptDecrypt(t *testing.T) {
	server, uriPrefix, tlsConfig := newServer(t)
	defer server.Close()

	client, err := hcvault.NewClient(uriPrefix, tlsConfig, token)
	if err != nil {
		t.Fatalf("hcvault.NewClient() err = %v, want nil", err)
	}

	keyURI := fmt.Sprintf(keyURITmpl, uriPrefix)
	aead, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(%q) err = %v, want nil", keyURI, err)
	}
	plaintext := []byte("plaintext")
	context := []byte("context")
	ciphertext, err := aead.Encrypt(plaintext, context)
	if err != nil {
		t.Fatalf("aead.Encrypt(plaintext, context) err = %v, want nil", err)
	}
	gotPlaintext, err := aead.Decrypt(ciphertext, context)
	if err != nil {
		t.Fatalf("aead.Decrypt(ciphertext, context) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("aead.Decrypt(ciphertext, context) = %s, want %s", gotPlaintext, plaintext)
	}

	invalidContext := []byte("invalidContext")
	_, err = aead.Decrypt(ciphertext, invalidContext)
	if err == nil {
		t.Error("aead.Decrypt(ciphertext, invalidContext) err = nil, want error")
	}
}

func TestVaultClientAEAD_DecryptWithFixedCiphertext(t *testing.T) {
	server, uriPrefix, tlsConfig := newServer(t)
	defer server.Close()

	client, err := hcvault.NewClient(uriPrefix, tlsConfig, token)
	if err != nil {
		t.Fatalf("hcvault.NewClient() err = %v, want nil", err)
	}

	keyURI := fmt.Sprintf(keyURITmpl, uriPrefix)
	aead, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(%q) err = %v, want nil", keyURI, err)
	}
	// associatedData is passed as "context" parameter to vault decrypt.
	plaintext := []byte("plaintext")
	context := []byte("context")
	ciphertext := fakeEncrypt(plaintext, nil, context)
	gotPlaintext, err := aead.Decrypt(ciphertext, context)
	if err != nil {
		t.Fatalf("aead.Decrypt(ciphertext, context) err = %v, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("aead.Decrypt(ciphertext, context) = %s, want %s", gotPlaintext, plaintext)
	}
}

func TestGetAEADFailWithBadKeyURI(t *testing.T) {
	server, uriPrefix, tlsConfig := newServer(t)
	defer server.Close()

	client, err := hcvault.NewClient(uriPrefix, tlsConfig, token)
	if err != nil {
		t.Fatalf("hcvault.NewClient() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name   string
		keyURI string
	}{
		{
			name:   "empty",
			keyURI: fmt.Sprintf("%s/", uriPrefix),
		},
		{
			name:   "without slash",
			keyURI: fmt.Sprintf("%s/badKeyUri", uriPrefix),
		},
		{
			name:   "with one slash",
			keyURI: fmt.Sprintf("%s/bad/KeyUri", uriPrefix),
		},
		{
			name:   "with three slash",
			keyURI: fmt.Sprintf("%s/one/two/three/four", uriPrefix),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.GetAEAD(test.keyURI); err == nil {
				t.Errorf("client.GetAEAD(%q) err = nil, want error", test.keyURI)
			}
		})
	}
}

// newVaultAPIClient creates a new vault API client
func newVaultAPIClient(t *testing.T, url string, token string, tlsConfig *tls.Config) *vault_api.Client {
	t.Helper()
	httpClient := vault_api.DefaultConfig().HttpClient
	transport := httpClient.Transport.(*http.Transport)
	transport.TLSClientConfig = tlsConfig.Clone()
	cfg := &vault_api.Config{
		Address:    url,
		HttpClient: httpClient,
	}
	client, err := vault_api.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(token)
	return client
}

type closeFunc func() error

// newServer returns a fake, TLS-enabled Vault server, an "hcvault://" URI
// prefix for accessing it, and a TLS configuration which trusts the servers
// certificate.
//
// Once finished with the server, it's Close() method should be called.
//
// The URL and TLS configuration can be passed to hcvault.NewClient().
//
// The URL can also be used to construct valid key URIs for the server.
func newServer(t *testing.T) (server *httptest.Server, uriPrefix string, clientTLSConfig *tls.Config) {
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				http.Error(w, "plaintext must be base64 encoded", 400)
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
				t.Fatalf("Cannot encode encrypted data: %v", err)
			}
			if _, err := w.Write(respBytes); err != nil {
				t.Fatalf("Cannot send encrypted data response: %v", err)
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
				t.Fatalf("Cannot encode encrypted data: %v", err)
			}
			if _, err := w.Write(respBytes); err != nil {
				t.Fatalf("Cannot send encrypted data response: %v", err)
			}

		default:
			http.NotFound(w, r)
		}
	}))

	uriPrefix = strings.Replace(server.URL, "https", "hcvault", 1)

	certpool := x509.NewCertPool()
	certpool.AddCert(server.Certificate())
	clientTLSConfig = &tls.Config{RootCAs: certpool}

	return server, uriPrefix, clientTLSConfig
}

// The ciphertext returned by HC Vault is of the form:
//
//	vault:v1:<ciphertext>
//
// where ciphertext is base64-encoded. See:
// https://developer.hashicorp.com/vault/api-docs/secret/transit#sample-request-13
//
// The ciphertext returned by this fake implementation is of the form:
//
//	enc:<context>:<associatedData>:<plaintext>
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
		t.Errorf("fakeEncrypt(plaintext, associatedData, context) = %q, want %q", got, want)
	}
}

func TestFakeEncryptWithoutAssociatedData(t *testing.T) {
	want := []byte("enc:Y29udGV4dA==::cGxhaW50ZXh0")
	got := fakeEncrypt([]byte("plaintext"), nil, []byte("context"))
	if !bytes.Equal(got, want) {
		t.Errorf("fakeEncrypt(plaintext, nil, context) = %q, want %q", got, want)
	}
}

func TestFakeEncryptWithoutContext(t *testing.T) {
	want := []byte("enc::YXNzb2NpYXRlZERhdGE=:cGxhaW50ZXh0")
	got := fakeEncrypt([]byte("plaintext"), []byte("associatedData"), nil)
	if !bytes.Equal(got, want) {
		t.Errorf("fakeEncrypt(plaintext, associatedData, nil) = %q, want %q", got, want)
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
		t.Errorf("fakeDecrypt() err = %v, want nil", err)
	}
	if want := []byte("plaintext"); !bytes.Equal(got, want) {
		t.Errorf("fakeDecrypt() = %q, want %q", got, want)
	}
}
