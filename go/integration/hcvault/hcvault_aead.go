// Copyright 2017 Google Inc.
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

// Package hcvault provides integration with the HashiCorp Vault.
package hcvault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/tink/go/tink"
	"github.com/hashicorp/vault/api"
)

// HCVaultAEAD represents a HashiCorp Vault service to a particular URI.
type HCVaultAEAD struct {
	keyURI string
	client *api.Logical
}

var _ tink.AEAD = (*HCVaultAEAD)(nil)

// NewHCVaultAEAD returns a new HashiCorp Vault service.
func NewHCVaultAEAD(keyURI string, client *api.Logical) *HCVaultAEAD {
	return &HCVaultAEAD{
		keyURI: keyURI,
		client: client,
	}
}

// Encrypt encrypts the plaintext data using a key stored in HashiCorp Vault.
// additionalData parameter must be either nil or zero-length.
func (a *HCVaultAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	if len(additionalData) > 0 {
		return nil, errors.New("additionalData is not supported")
	}
	encryptionPath, err := a.getEncryptionPath(a.keyURI)
	if err != nil {
		return nil, err
	}
	req := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	secret, err := a.client.Write(encryptionPath, req)
	if err != nil {
		return nil, err
	}
	ciphertext := secret.Data["ciphertext"].(string)
	return []byte(ciphertext), nil
}

// Decrypt decrypts the ciphertext using a key stored in HashiCorp Vault.
// additionalData parameter must be either nil or zero-length.
func (a *HCVaultAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	if len(additionalData) > 0 {
		return nil, errors.New("additionalData is not supported")
	}
	decryptionPath, err := a.getDecryptionPath(a.keyURI)
	if err != nil {
		return nil, err
	}
	req := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}
	secret, err := a.client.Write(decryptionPath, req)
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
func (a *HCVaultAEAD) getEncryptionPath(keyURL string) (string, error) {
	key, err := a.extractKey(keyURL)
	if err != nil {
		return "", err
	}
	parts := strings.Split(key, "/")
	parts[len(parts)-2] = "encrypt"
	return strings.Join(parts, "/"), nil
}

// getDecryptionPath transforms keyURL to a Vault decryption path.
// For example a keyURL "transit/keys/key-foo" will be transformed to "transit/decrypt/key-foo".
func (a *HCVaultAEAD) getDecryptionPath(keyURL string) (string, error) {
	key, err := a.extractKey(keyURL)
	if err != nil {
		return "", err
	}
	parts := strings.Split(key, "/")
	parts[len(parts)-2] = "decrypt"
	return strings.Join(parts, "/"), nil
}

var vaultKeyRegex = regexp.MustCompile(fmt.Sprintf("^%s/*([a-zA-Z0-9.:]+)/(.*)$", vaultPrefix))

func (a *HCVaultAEAD) extractKey(keyURL string) (string, error) {
	m := vaultKeyRegex.FindAllStringSubmatch(keyURL, -1)
	if m == nil {
		return "", errors.New("malformed keyURL")
	}
	return m[0][2], nil
}
