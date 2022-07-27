// Copyright 2022 Google LLC
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

package subtle

import (
	"bytes"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	hpkepb "github.com/google/tink/go/proto/hpke_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	// HPKE public key length from
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
	hpkeX25519HKDFSHA256PubKeyLen = 32

	hpkePublicKeyTypeURL  = "type.googleapis.com/google.crypto.tink.HpkePublicKey"
	hpkePrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
)

// SerializePrimaryPublicKey serializes a public keyset handle's primary key if
// the primary key is a public key and matches both the template argument and a
// supported template.
//
// Supported templates are the same as KeysetHandleFromSerializedPublicKey's:
//   - DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template,
//     which returns the KEM-encoding of the public key, i.e. SerializePublicKey
//     in https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1.
func SerializePrimaryPublicKey(handle *keyset.Handle, template *tinkpb.KeyTemplate) ([]byte, error) {
	templateParams, err := hpkeParamsFromTemplate(template)
	if err != nil {
		return nil, fmt.Errorf("failed to verify key template: %v", err)
	}

	// Create keyset from handle.
	w := new(bytes.Buffer)
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(w)); err != nil {
		return nil, fmt.Errorf("failed to write key: %v", err)
	}
	ks := &tinkpb.Keyset{}
	if err := proto.Unmarshal(w.Bytes(), ks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Keyset %v: %v", ks, err)
	}
	if len(ks.GetKey()) < 1 {
		return nil, errors.New("empty keyset")
	}

	// Verify and return handle's primary key.
	for _, key := range ks.GetKey() {
		if key.GetStatus() != tinkpb.KeyStatusType_ENABLED ||
			key.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW ||
			key.GetKeyId() != ks.GetPrimaryKeyId() {
			continue
		}

		keyData := key.GetKeyData()
		if keyData.GetKeyMaterialType() != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
			return nil, errors.New("primary key is not asymmetric public")
		}
		if keyData.GetTypeUrl() != hpkePublicKeyTypeURL {
			return nil, fmt.Errorf("primary key does not have key type URL %s", hpkePublicKeyTypeURL)
		}

		hpkeKey := &hpkepb.HpkePublicKey{}
		if err := proto.Unmarshal(keyData.GetValue(), hpkeKey); err != nil {
			return nil, fmt.Errorf("failed to unmarshal HpkePublicKey %v: %v", hpkeKey, err)
		}
		// Check equality between HPKE params in handle's primary key and in
		// template, as template's params have already been verified.
		if !proto.Equal(templateParams, hpkeKey.GetParams()) {
			return nil, errors.New("HPKE params in handle and template are not equal")
		}

		return hpkeKey.GetPublicKey(), nil
	}

	return nil, errors.New("no valid primary HPKE public key in keyset")
}

// KeysetHandleFromSerializedPublicKey returns a keyset handle containing a
// primary key that has the specified pubKeyBytes and matches template.
//
// Supported templates are the same as PublicKeyFromPrimaryKey's:
//   - DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template,
//     which requires pubKeyBytes to be the KEM-encoding of the public key, i.e.
//     SerializePublicKey in
//     https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1.
func KeysetHandleFromSerializedPublicKey(pubKeyBytes []byte, template *tinkpb.KeyTemplate) (*keyset.Handle, error) {
	params, err := hpkeParamsFromTemplate(template)
	if err != nil {
		return nil, fmt.Errorf("failed to verify key template: %v", err)
	}
	if len(pubKeyBytes) != hpkeX25519HKDFSHA256PubKeyLen {
		return nil, fmt.Errorf("pubKeyBytes length is %d but should be %d", len(pubKeyBytes), hpkeX25519HKDFSHA256PubKeyLen)
	}

	pubKey := &hpkepb.HpkePublicKey{
		Version:   0,
		Params:    params,
		PublicKey: pubKeyBytes,
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HpkePublicKey %v: %v", pubKey, err)
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         hpkePublicKeyTypeURL,
					Value:           serializedPubKey,
					KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	return keyset.NewHandleWithNoSecrets(ks)
}

// hpkeParamsFromTemplate returns HPKE params after verifying that template is
// supported.
//
// Supported templates include:
//   - DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template.
func hpkeParamsFromTemplate(template *tinkpb.KeyTemplate) (*hpkepb.HpkeParams, error) {
	if template.GetTypeUrl() != hpkePrivateKeyTypeURL {
		return nil, fmt.Errorf("not key type URL %s", hpkePrivateKeyTypeURL)
	}
	if template.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
		return nil, errors.New("not raw output prefix type")
	}
	keyFormat := &hpkepb.HpkeKeyFormat{}
	if err := proto.Unmarshal(template.GetValue(), keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal HpkeKeyFormat(%v): %v", template.GetValue(), err)
	}

	params := keyFormat.GetParams()
	if kem := params.GetKem(); kem != hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256 {
		return nil, fmt.Errorf("HPKE KEM %s not supported", kem)
	}
	if kdf := params.GetKdf(); kdf != hpkepb.HpkeKdf_HKDF_SHA256 {
		return nil, fmt.Errorf("HPKE KDF %s not supported", kdf)
	}
	if aead := params.GetAead(); aead != hpkepb.HpkeAead_CHACHA20_POLY1305 {
		return nil, fmt.Errorf("HPKE AEAD %s not supported", aead)
	}

	return params, nil
}
