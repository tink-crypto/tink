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

package gcpkms

import (
	"encoding/base64"

	"google.golang.org/api/cloudkms/v1"

	"github.com/google/tink/go/tink"
)

// gcpAEAD represents a GCP KMS service to a particular URI.
type gcpAEAD struct {
	keyURI string
	kms    cloudkms.Service
}

var _ tink.AEAD = (*gcpAEAD)(nil)

// newGCPAEAD returns a new GCP KMS service.
func newGCPAEAD(keyURI string, kms *cloudkms.Service) tink.AEAD {
	return &gcpAEAD{
		keyURI: keyURI,
		kms:    *kms,
	}
}

// Encrypt encrypts the plaintext with associatedData.
func (a *gcpAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {

	req := &cloudkms.EncryptRequest{
		Plaintext:                   base64.URLEncoding.EncodeToString(plaintext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(associatedData),
	}
	resp, err := a.kms.Projects.Locations.KeyRings.CryptoKeys.Encrypt(a.keyURI, req).Do()
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}

// Decrypt decrypts ciphertext with with associatedData.
func (a *gcpAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {

	req := &cloudkms.DecryptRequest{
		Ciphertext:                  base64.URLEncoding.EncodeToString(ciphertext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(associatedData),
	}
	resp, err := a.kms.Projects.Locations.KeyRings.CryptoKeys.Decrypt(a.keyURI, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}
