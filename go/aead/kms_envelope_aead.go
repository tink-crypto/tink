// Copyright 2019 Google LLC
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

package aead

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	lenDEK        = 4
	maxUint32Size = 4294967295
)

// KMSEnvelopeAEAD represents an instance of Envelope AEAD.
type KMSEnvelopeAEAD struct {
	dekTemplate *tinkpb.KeyTemplate
	remote      tink.AEAD
	// if err != nil, then the primitive will always fail with this error.
	// this is needed because NewKMSEnvelopeAEAD2 doesn't return an error.
	err error
}

var tinkAEADKeyTypes map[string]bool = map[string]bool{
	aesCTRHMACAEADTypeURL:    true,
	aesGCMTypeURL:            true,
	chaCha20Poly1305TypeURL:  true,
	xChaCha20Poly1305TypeURL: true,
	aesGCMSIVTypeURL:         true,
}

func isSupporedKMSEnvelopeDEK(dekKeyTypeURL string) bool {
	_, found := tinkAEADKeyTypes[dekKeyTypeURL]
	return found
}

// NewKMSEnvelopeAEAD2 creates an new instance of KMSEnvelopeAEAD.
//
// dekTemplate must be a KeyTemplate for any of these Tink AEAD key types (any
// other key template will be rejected):
//   - AesCtrHmacAeadKey
//   - AesGcmKey
//   - ChaCha20Poly1305Key
//   - XChaCha20Poly1305
//   - AesGcmSivKey
func NewKMSEnvelopeAEAD2(dekTemplate *tinkpb.KeyTemplate, remote tink.AEAD) *KMSEnvelopeAEAD {
	if !isSupporedKMSEnvelopeDEK(dekTemplate.GetTypeUrl()) {
		return &KMSEnvelopeAEAD{
			remote:      nil,
			dekTemplate: nil,
			err:         fmt.Errorf("unsupported DEK key type %s", dekTemplate.GetTypeUrl()),
		}
	}
	return &KMSEnvelopeAEAD{
		remote:      remote,
		dekTemplate: dekTemplate,
		err:         nil,
	}
}

// Encrypt implements the tink.AEAD interface for encryption.
func (a *KMSEnvelopeAEAD) Encrypt(pt, aad []byte) ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}
	dekKeyData, err := registry.NewKeyData(a.dekTemplate)
	if err != nil {
		return nil, err
	}
	dek := dekKeyData.GetValue()
	encryptedDEK, err := a.remote.Encrypt(dek, []byte{})
	if err != nil {
		return nil, err
	}
	p, err := registry.Primitive(a.dekTemplate.TypeUrl, dek)
	if err != nil {
		return nil, err
	}
	primitive, ok := p.(tink.AEAD)
	if !ok {
		return nil, errors.New("kms_envelope_aead: failed to convert AEAD primitive")
	}

	payload, err := primitive.Encrypt(pt, aad)
	if err != nil {
		return nil, err
	}
	if len(encryptedDEK) > maxUint32Size {
		return nil, errors.New("kms_envelope_aead: encrypted dek too large")
	}
	res := make([]byte, 0, lenDEK+len(encryptedDEK)+len(payload))
	res = binary.BigEndian.AppendUint32(res, uint32(len(encryptedDEK)))
	res = append(res, encryptedDEK...)
	res = append(res, payload...)
	return res, nil
}

// Decrypt implements the tink.AEAD interface for decryption.
func (a *KMSEnvelopeAEAD) Decrypt(ct, aad []byte) ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}
	// Verify we have enough bytes for the length of the encrypted DEK.
	if len(ct) <= lenDEK {
		return nil, errors.New("kms_envelope_aead: invalid ciphertext")
	}

	// Extract length of encrypted DEK and advance past that length.
	ed := int(binary.BigEndian.Uint32(ct[:lenDEK]))
	ct = ct[lenDEK:]

	// Verify we have enough bytes for the encrypted DEK.
	if ed <= 0 || len(ct) < ed {
		return nil, errors.New("kms_envelope_aead: invalid ciphertext")
	}

	// Extract the encrypted DEK and the payload.
	encryptedDEK := ct[:ed]
	payload := ct[ed:]
	ct = nil

	// Decrypt the DEK.
	dek, err := a.remote.Decrypt(encryptedDEK, []byte{})
	if err != nil {
		return nil, err
	}

	// Get an AEAD primitive corresponding to the DEK.
	p, err := registry.Primitive(a.dekTemplate.TypeUrl, dek)
	if err != nil {
		return nil, fmt.Errorf("kms_envelope_aead: %s", err)
	}
	primitive, ok := p.(tink.AEAD)
	if !ok {
		return nil, errors.New("kms_envelope_aead: failed to convert AEAD primitive")
	}

	// Decrypt the payload.
	return primitive.Decrypt(payload, aad)
}
