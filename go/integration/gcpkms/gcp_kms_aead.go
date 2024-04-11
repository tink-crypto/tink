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

package gcpkms

import (
	"encoding/base64"
	"fmt"
	"hash/crc32"

	"google.golang.org/api/cloudkms/v1"

	"github.com/google/tink/go/tink"
)

// gcpAEAD represents a GCP KMS service to a particular URI.
type gcpAEAD struct {
	keyName string
	kms     cloudkms.Service
}

var _ tink.AEAD = (*gcpAEAD)(nil)

// newGCPAEAD returns a new GCP KMS service.
func newGCPAEAD(keyName string, kms *cloudkms.Service) tink.AEAD {
	return &gcpAEAD{
		keyName: keyName,
		kms:     *kms,
	}
}

// Encrypt calls GCP KMS to encrypt the plaintext with associatedData and returns the resulting ciphertext.
// It returns an error if the call to KMS fails or if the response returned by KMS does not pass integrity verification
// (http://cloud.google.com/kms/docs/data-integrity-guidelines#calculating_and_verifying_checksums).
func (a *gcpAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {

	req := &cloudkms.EncryptRequest{
		Plaintext:                         base64.URLEncoding.EncodeToString(plaintext),
		PlaintextCrc32c:                   computeChecksum(plaintext),
		AdditionalAuthenticatedData:       base64.URLEncoding.EncodeToString(associatedData),
		AdditionalAuthenticatedDataCrc32c: computeChecksum(associatedData),
		// Send the integrity verification fields even if their value is 0.
		ForceSendFields: []string{"PlaintextCrc32c", "AdditionalAuthenticatedDataCrc32c"},
	}

	resp, err := a.kms.Projects.Locations.KeyRings.CryptoKeys.Encrypt(a.keyName, req).Do()
	if err != nil {
		return nil, err
	}

	if !resp.VerifiedPlaintextCrc32c {
		return nil, fmt.Errorf("KMS request for %q is missing the checksum field plaintext_crc32c, and other information may be missing from the response. Please retry a limited number of times in case the error is transient", a.keyName)
	}
	if !resp.VerifiedAdditionalAuthenticatedDataCrc32c {
		return nil, fmt.Errorf("KMS request for %q is missing the checksum field additional_authenticated_data_crc32c, and other information may be missing from the response. Please retry a limited number of times in case the error is transient", a.keyName)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, err
	}
	if resp.CiphertextCrc32c != computeChecksum(ciphertext) {
		return nil, fmt.Errorf("KMS response corrupted in transit for %q: the checksum in field ciphertext_crc32c did not match the data in field ciphertext. Please retry in case this is a transient error", a.keyName)
	}

	return ciphertext, nil
}

// Decrypt calls GCP KMS to decrypt the ciphertext with with associatedData and returns the resulting plaintext.
// It returns an error if the call to KMS fails or if the response returned by KMS does not pass integrity verification
// (http://cloud.google.com/kms/docs/data-integrity-guidelines#calculating_and_verifying_checksums).
func (a *gcpAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {

	req := &cloudkms.DecryptRequest{
		Ciphertext:                        base64.URLEncoding.EncodeToString(ciphertext),
		CiphertextCrc32c:                  computeChecksum(ciphertext),
		AdditionalAuthenticatedData:       base64.URLEncoding.EncodeToString(associatedData),
		AdditionalAuthenticatedDataCrc32c: computeChecksum(associatedData),
		// Send the integrity verification fields even if their value is 0.
		ForceSendFields: []string{"CiphertextCrc32c", "AdditionalAuthenticatedDataCrc32c"},
	}

	resp, err := a.kms.Projects.Locations.KeyRings.CryptoKeys.Decrypt(a.keyName, req).Do()
	if err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, err
	}
	if resp.PlaintextCrc32c != computeChecksum(plaintext) {
		return nil, fmt.Errorf("KMS response corrupted in transit for %q: the checksum in field plaintext_crc32c did not match the data in field plaintext. Please retry in case this is a transient error", a.keyName)
	}
	return plaintext, nil
}

// crc32cTable is used to compute checksums. It is defined as a package level variable to avoid
// re-computation on every CRC calculation.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// computeChecksum returns the checksum that corresponds to the input value as an int64.
func computeChecksum(value []byte) int64 {
	return int64(crc32.Checksum(value, crc32cTable))
}
