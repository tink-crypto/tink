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

// Package fakekms provides a fake implementation of registry.KMSClient.
//
// Normally, a 'keyURI' identifies a key that is stored remotely by the KMS,
// and every operation is executed remotely using a RPC call to the KMS, since
// the key should not be sent to the client.
// In this fake implementation we want to avoid these RPC calls. We achieve this
// by encoding the key in the 'keyURI'. So the client simply needs to decode
// the key and generate an AEAD out of it. This is of course insecure and should
// only be used in testing.
package fakekms

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/tink"
)

const fakePrefix = "fake-kms://"

var _ registry.KMSClient = (*fakeClient)(nil)

type fakeClient struct {
	uriPrefix string
}

// NewClient returns a fake KMS client which will handle keys with uriPrefix prefix.
// keyURI must have the following format: 'fake-kms://<base64 encoded aead keyset>'.
func NewClient(uriPrefix string) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), fakePrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %s, but got %s", fakePrefix, uriPrefix)
	}
	return &fakeClient{
		uriPrefix: uriPrefix,
	}, nil
}

// Supported returns true if this client does support keyURI.
func (c *fakeClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.uriPrefix)
}

// GetAEAD returns an AEAD by keyURI.
func (c *fakeClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("keyURI must start with prefix %s, but got %s", c.uriPrefix, keyURI)
	}
	encodeKeyset := strings.TrimPrefix(keyURI, fakePrefix)
	keysetData, err := base64.RawURLEncoding.DecodeString(encodeKeyset)
	if err != nil {
		return nil, err
	}
	reader := keyset.NewBinaryReader(bytes.NewReader(keysetData))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return nil, err
	}
	return aead.New(handle)
}

// NewKeyURI returns a new, random fake KMS key URI.
func NewKeyURI() (string, error) {
	handle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = testkeyset.Write(handle, writer)
	if err != nil {
		return "", err
	}
	return fakePrefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}
