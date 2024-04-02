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

package hcvault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/google/tink/go/tink"
)

// vaultAEAD represents a HashiCorp Vault service to a particular URI.
type vaultAEAD struct {
	encKeyPath         string
	decKeyPath         string
	client             *api.Logical
	associatedDataName string
}

var _ tink.AEAD = (*vaultAEAD)(nil)

const (
	encryptSegment            = "encrypt"
	decryptSegment            = "decrypt"
	defaultAssociatedDataName = "associated_data"
	legacyAssociatedDataName  = "context"
)

// AEADOption is an interface for defining options that are passed to [NewAEAD].
type AEADOption interface{ set(*vaultAEAD) error }

type option func(*vaultAEAD) error

func (o option) set(a *vaultAEAD) error { return o(a) }

// WithLegacyContextParamater lets the remote AEAD populate the "context" parameter
// in encrypt and decrypt requests instead of the "associated_data".
//
// Using this option makes the AEAD compatible with the instance returned by GetAEAD
// from the KMSClient returned by NewClient. For new keys, this option should not be used.
//
// ## Warning
//
// Vault only uses the "context" parameter for keys which have derivation enabled
// (with "derived=true") and ignores it otherwise. For such keys, the "context"
// parameter is required to be non-empty.
//
// Therefore:
// - for keys with "derived=false", you should only use empty associated data.
// - for keys with "derived=true", you should only use non-empty associated data.
//
// With Tink's "KMS envelope AEAD", always use a key with "derived=false".
//
// For reference, see https://developer.hashicorp.com/vault/api-docs/secret/transit.
func WithLegacyContextParamater() AEADOption {
	return option(func(a *vaultAEAD) error {
		a.associatedDataName = legacyAssociatedDataName
		return nil
	})
}

// NewAEAD returns a new remote AEAD primitive for a HashiCorp Vault service.
func NewAEAD(keyPath string, client *api.Logical, opts ...AEADOption) (tink.AEAD, error) {
	encKeyPath, decKeyPath, err := getEndpointPaths(keyPath)
	if err != nil {
		return nil, err
	}
	a := &vaultAEAD{
		encKeyPath:         encKeyPath,
		decKeyPath:         decKeyPath,
		client:             client,
		associatedDataName: defaultAssociatedDataName,
	}
	// Process options, if any.
	for _, opt := range opts {
		if err := opt.set(a); err != nil {
			return nil, fmt.Errorf("failed setting option: %v", err)
		}
	}
	return a, nil
}

func extractCiphertext(secret *api.Secret) ([]byte, error) {
	if secret == nil {
		return nil, errors.New("secret is nil")
	}
	c, ok := secret.Data["ciphertext"]
	if !ok {
		return nil, errors.New("no ciphertext")
	}
	ciphertext, ok := c.(string)
	if !ok {
		return nil, errors.New("invalid ciphertext")
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}
	return []byte(ciphertext), nil
}

// Encrypt encrypts the plaintext data using a key stored in HashiCorp Vault.
func (a *vaultAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	// Create an encryption request map according to Vault REST API:
	// https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data.
	req := map[string]any{
		"plaintext":          base64.StdEncoding.EncodeToString(plaintext),
		a.associatedDataName: base64.StdEncoding.EncodeToString(associatedData),
	}
	secret, err := a.client.Write(a.encKeyPath, req)
	if err != nil {
		return nil, err
	}
	return extractCiphertext(secret)
}

func extractPlaintext(secret *api.Secret) ([]byte, error) {
	// Note that when a valid ciphertext of the empty string is decrypted,
	// secret.Data["plaintext"] may not be set. So we allow that.
	if secret == nil {
		return []byte{}, nil
	}
	p, ok := secret.Data["plaintext"]
	if !ok {
		return []byte{}, nil
	}
	plaintext64, ok := p.(string)
	if !ok {
		return nil, errors.New("invalid plaintext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(plaintext64)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Decrypt decrypts the ciphertext using a key stored in HashiCorp Vault.
func (a *vaultAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	// Create a decryption request map according to Vault REST API:
	// https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data.
	req := map[string]any{
		"ciphertext":         string(ciphertext),
		a.associatedDataName: base64.StdEncoding.EncodeToString(associatedData),
	}
	secret, err := a.client.Write(a.decKeyPath, req)
	if err != nil {
		return nil, err
	}
	return extractPlaintext(secret)
}

// getEndpointPaths transforms keyPath into the Vault transit encrypt and decrypt
// paths. The keyPath is expected to have the form "/{mount-path}/keys/{keyName}", which will
// be transformed to
// "{mount-path}/encrypt/{keyName}" and "{mount-path}/decrypt/{keyName}".
func getEndpointPaths(keyPath string) (encryptPath, decryptPath string, err error) {
	parts := strings.Split(keyPath, "/")
	length := len(parts)
	if length < 4 || parts[0] != "" || parts[length-2] != "keys" {
		return "", "", errors.New("malformed keyPath")
	}

	parts[length-2] = encryptSegment
	encryptPath = strings.Join(parts[1:], "/")
	parts[length-2] = decryptSegment
	decryptPath = strings.Join(parts[1:], "/")
	return encryptPath, decryptPath, nil
}
