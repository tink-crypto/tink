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

	"github.com/google/tink/go/tink"
	"github.com/hashicorp/vault/api"
)

// vaultAEAD represents a HashiCorp Vault service to a particular URI.
type vaultAEAD struct {
	encKeyPath string
	decKeyPath string
	client     *api.Logical
}

var _ tink.AEAD = (*vaultAEAD)(nil)

const (
	encryptSegment = "encrypt"
	decryptSegment = "decrypt"
)

// newHCVaultAEAD returns a new HashiCorp Vault service.
func newHCVaultAEAD(keyURI string, client *api.Logical) (tink.AEAD, error) {
	encKeyPath, decKeyPath, err := getEndpointPaths(keyURI)
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

// getEndpointPaths transforms keyURL into the Vault transit encrypt and decrypt
// paths. The keyURL is expected to end in "/{mount}/keys/{keyName}". For
// example, the keyURL "hcvault:///transit/keys/key-foo" will be transformed to
// "transit/encrypt/key-foo" and "transit/decrypt/key-foo", and
// "hcvault://my-vault.example.com/teams/billing/service/cipher/keys/key-bar"
// will be transformed into
// "hcvault://my-vault.example.com/teams/billing/service/cipher/encrypt/key-bar"
// and
// "hcvault://my-vault.example.com/teams/billing/service/cipher/decrypt/key-bar".
func getEndpointPaths(keyURL string) (encryptPath, decryptPath string, err error) {
	u, err := url.Parse(keyURL)
	if err != nil || u.Scheme != "hcvault" {
		return "", "", errors.New("malformed keyURL")
	}

	parts := strings.Split(u.EscapedPath(), "/")
	length := len(parts)
	if length < 4 || parts[length-2] != "keys" {
		return "", "", errors.New("malformed keyURL")
	}

	parts[length-2] = encryptSegment
	encryptPath = strings.Join(parts[1:], "/")
	parts[length-2] = decryptSegment
	decryptPath = strings.Join(parts[1:], "/")
	return encryptPath, decryptPath, nil
}
