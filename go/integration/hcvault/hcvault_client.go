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

// Package hcvault provides integration with the HashiCorp Vault (https://www.vaultproject.io/).
// Below there is an example of how the integration code can be used:

// package main
//
// import (
// 	"fmt"
// 	"log"
//
// 	"github.com/google/tink/go/aead"
// 	"github.com/google/tink/go/core/registry"
// 	"github.com/google/tink/go/integration/hcvault"
// 	"github.com/google/tink/go/keyset"
// )
//
// const (
// 	keyURI = "hcvault://hcvault.corp.com:8200/transit/keys/key-1"
// )
//
// func main() {
//  tlsConf := getTLSConfig()
//  token := getVaultToken()
//  vaultClient, err := hcvault.NewHCVaultClient(keyURI, tlsConf, token)
// 	if err != nil {
//    // handle error
// 	}
// 	registry.RegisterKMSClient(vaultClient)
//
// 	dek := aead.AES128CTRHMACSHA256KeyTemplate()
// 	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
// 	if err != nil {
//    // handle error
// 	}
// 	a, err := aead.New(kh)
// 	if err != nil {
//    // handle error
// 	}
//
// 	msg := "secret message"
// 	ct, err := a.Encrypt([]byte(msg), nil)
// 	if err != nil {
//    // handle error
// 	}
//
// 	pt, err := a.Decrypt(ct, nil)
// 	if err != nil {
//    // handle error
// 	}
// }

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

// HCVaultClient represents a client that connects to the HashiCorp Vault backend.
type HCVaultClient struct {
	keyURI string
	client *api.Logical
}

var _ registry.KMSClient = (*HCVaultClient)(nil)

// NewHCVaultClient returns a new client to HashiCorp Vault.
func NewHCVaultClient(uri string, tlsCfg *tls.Config, token string) (*HCVaultClient, error) {
	if tlsCfg == nil {
		return nil, errors.New("TLS configuration must be provided")
	}
	return newClient(uri, tlsCfg, token, "https")
}

// NewInsecureHCVaultClient returns a new client to HashiCorp Vault.
// The returned client will use insecure HTTP protocol to communicate with
// Vault backend.
// It is NOT RECOMMENDED to use this function in production.
func NewInsecureHCVaultClient(uri string, token string) (*HCVaultClient, error) {
	return newClient(uri, nil, token, "http")
}

func newClient(uri string, tlsCfg *tls.Config, token, protocol string) (*HCVaultClient, error) {
	if !strings.HasPrefix(strings.ToLower(uri), vaultPrefix) {
		return nil, fmt.Errorf("key URI must start with %s", vaultPrefix)
	}

	httpClient := api.DefaultConfig().HttpClient
	transport := httpClient.Transport.(*http.Transport)
	transport.TLSClientConfig = tlsCfg

	vurl, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	cfg := &api.Config{
		Address:    protocol + "://" + vurl.Host,
		HttpClient: httpClient,
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	return &HCVaultClient{
		keyURI: uri,
		client: client.Logical(),
	}, nil

}

// Supported returns true if this client does support keyURI.
func (c *HCVaultClient) Supported(keyURI string) bool {
	return strings.ToLower(c.keyURI) == strings.ToLower(keyURI)
}

// GetAEAD gets an AEAD backend by keyURI.
func (c *HCVaultClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if strings.ToLower(c.keyURI) != strings.ToLower(keyURI) {
		return nil, fmt.Errorf("this client is bound to %s, cannot load keys bound to %s", c.keyURI, keyURI)
	}
	return NewHCVaultAEAD(keyURI, c.client), nil
}
