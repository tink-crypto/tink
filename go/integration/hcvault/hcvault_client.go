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

// Package hcvault provides integration with the [HashiCorp Vault].
//
//	[HashiCorp Vault]: https://www.vaultproject.io/.
package hcvault

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
	"github.com/hashicorp/vault/api"
)

const (
	vaultPrefix = "hcvault://"
)

// vaultClient represents a client that connects to the HashiCorp Vault backend.
type vaultClient struct {
	keyURIPrefix string
	client       *api.Logical
}

var _ registry.KMSClient = (*vaultClient)(nil)

// NewClient returns a new client to HashiCorp Vault.
// uriPrefix parameter is a valid URI which must have "hcvault" scheme and
// vault server address and port. Specific key URIs will be matched against this
// prefix to determine if the client supports the key or not.
// tlsCfg represents tls.Config which will be used to communicate with Vault
// server via HTTPS protocol. If not specified a default tls.Config{} will be
// used.
func NewClient(uriPrefix string, tlsCfg *tls.Config, token string) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), vaultPrefix) {
		return nil, fmt.Errorf("key URI must start with %s", vaultPrefix)
	}

	httpClient := api.DefaultConfig().HttpClient
	transport := httpClient.Transport.(*http.Transport)
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	transport.TLSClientConfig = tlsCfg

	vurl, err := url.Parse(uriPrefix)
	if err != nil {
		return nil, err
	}

	cfg := &api.Config{
		Address:    "https://" + vurl.Host,
		HttpClient: httpClient,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	return &vaultClient{
		keyURIPrefix: uriPrefix,
		client:       client.Logical(),
	}, nil

}

// Supported returns true if this client does support keyURI.
func (c *vaultClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD gets an AEAD backend by keyURI.
func (c *vaultClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, errors.New("unsupported keyURI")
	}

	return newHCVaultAEAD(keyURI, c.client)
}
