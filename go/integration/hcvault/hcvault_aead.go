// Copyright 2019 Google Inc.
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

package hcvault

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/google/tink/go/tink"
)

// vaultAEAD represents a HashiCorp Vault service to a particular URI.
type vaultAEAD struct {
	encKeyPath string
	decKeyPath string
	client     *api.Logical
}

var _ tink.AEAD = (*vaultAEAD)(nil)

// newHCVaultAEAD returns a new HashiCorp Vault service.
func newHCVaultAEAD(keyURI string, client *api.Logical) (tink.AEAD, error) {
	encKeyPath, err := getEncryptionPath(keyURI)
	if err != nil {
		return nil, err
	}
	decKeyPath, err := getDecryptionPath(keyURI)
	if err != nil {
		return nil, err
	}
	return &vaultAEAD{
		encKeyPath: encKeyPath,
		decKeyPath: decKeyPath,
		client:     client,
	}, nil
}

// Encrypt encrypts the plaintext data using a key stored in HashiCorp Vault.
// associatedData parameter is used as a context for key derivation, more
// information available https://www.vaultproject.io/docs/secrets/transit/index.html.
func (a *vaultAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	// Create an encryption request map according to Vault REST API:
	// https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data.
	req := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		"context":   base64.StdEncoding.EncodeToString(associatedData),
	}
	secret, err := a.client.Write(a.encKeyPath, req)
	if err != nil {
		return nil, err
	}
	ciphertext := secret.Data["ciphertext"].(string)
	return []byte(ciphertext), nil
}

// Decrypt decrypts the ciphertext using a key stored in HashiCorp Vault.
// associatedData parameter is used as a context for key derivation, more
// information available https://www.vaultproject.io/docs/secrets/transit/index.html.
func (a *vaultAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	// Create a decryption request map according to Vault REST API:
	// https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data.
	req := map[string]interface{}{
		"ciphertext": string(ciphertext),
		"context":    base64.StdEncoding.EncodeToString(associatedData),
	}
	secret, err := a.client.Write(a.decKeyPath, req)
	if err != nil {
		return nil, err
	}
	plaintext64 := secret.Data["plaintext"].(string)
	plaintext, err := base64.StdEncoding.DecodeString(plaintext64)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// getEncryptionPath transforms keyURL to a Vault encryption path.
// For example a keyURL "transit/keys/key-foo" will be transformed to "transit/encrypt/key-foo".
func getEncryptionPath(keyURL string) (string, error) {
	key, err := extractKey(keyURL)
	if err != nil {
		return "", err
	}
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		// key must have the form "transit/keys/<name>", so it must have exactly two slashes
		return "", errors.New("malformed keyURL")
	}
	parts[1] = "encrypt"
	return strings.Join(parts, "/"), nil
}

// getDecryptionPath transforms keyURL to a Vault decryption path.
// For example a keyURL "transit/keys/key-foo" will be transformed to "transit/decrypt/key-foo".
func getDecryptionPath(keyURL string) (string, error) {
	key, err := extractKey(keyURL)
	if err != nil {
		return "", err
	}
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		// key must have the form "transit/keys/<name>", so it must have exactly two slashes
		return "", errors.New("malformed keyURL")
	}
	parts[1] = "decrypt"
	return strings.Join(parts, "/"), nil
}

func extractKey(keyURL string) (string, error) {
	u, err := url.Parse(keyURL)
	if err != nil || u.Scheme != "hcvault" || len(u.Path) == 0 {
		return "", errors.New("malformed keyURL")
	}
	return u.EscapedPath()[1:], nil
}
