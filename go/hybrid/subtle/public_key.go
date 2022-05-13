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
	hpkePublicKeyTypeURL  = "type.googleapis.com/google.crypto.tink.HpkePublicKey"
	hpkePrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
)

// PublicKeyFromPrimaryKey returns the public key bytes from handle's primary
// key if 1) the primary key's key data matches template and 2) template is
// listed as a supported below.
//
// Supported key templates include:
//   * DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template,
//     which specifically returns the KEM-encoding (i.e. SerializePublicKey() in
//     https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.3)
func PublicKeyFromPrimaryKey(handle *keyset.Handle, template *tinkpb.KeyTemplate) ([]byte, error) {
	// Verify key template.
	if template.GetTypeUrl() != hpkePrivateKeyTypeURL {
		return nil, fmt.Errorf("template does not have key type URL %s", hpkePrivateKeyTypeURL)
	}
	if template.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
		return nil, errors.New("template does not have raw output prefix type")
	}
	templateKeyFormat := &hpkepb.HpkeKeyFormat{}
	if err := proto.Unmarshal(template.GetValue(), templateKeyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal HpkeKeyFormat: %v", err)
	}
	if err := supportedHPKEParams(templateKeyFormat.GetParams()); err != nil {
		return nil, err
	}

	// Create keyset from handle.
	keysetBytes := new(bytes.Buffer)
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(keysetBytes)); err != nil {
		return nil, fmt.Errorf("failed to write key: %v", err)
	}
	keyset := &tinkpb.Keyset{}
	if err := proto.Unmarshal(keysetBytes.Bytes(), keyset); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Keyset: %v", err)
	}
	if len(keyset.GetKey()) < 1 {
		return nil, errors.New("empty keyset")
	}

	// Verify and return handle's primary key.
	for _, key := range keyset.GetKey() {
		if key.GetStatus() != tinkpb.KeyStatusType_ENABLED ||
			key.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW ||
			key.GetKeyId() != keyset.GetPrimaryKeyId() {
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
			return nil, fmt.Errorf("failed to unmarshal HpkePublicKey: %v", err)
		}
		// Check equality between HPKE params in handle's primary key and in
		// template, as template's params have already been verified.
		if !proto.Equal(templateKeyFormat.GetParams(), hpkeKey.GetParams()) {
			return nil, errors.New("HPKE params in handle and template are not equal")
		}

		return hpkeKey.GetPublicKey(), nil
	}

	return nil, errors.New("no valid primary HPKE public key in keyset")
}

// supportedHPKEParams implements the restrictions on HPKE params enforced by
// PublicKeyFromPrimaryKey's supported key templates.
func supportedHPKEParams(params *hpkepb.HpkeParams) error {
	if kem := params.GetKem(); kem != hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256 {
		return fmt.Errorf("HPKE KEM %s not supported", kem)
	}
	if kdf := params.GetKdf(); kdf != hpkepb.HpkeKdf_HKDF_SHA256 {
		return fmt.Errorf("HPKE KDF %s not supported", kdf)
	}
	if aead := params.GetAead(); aead != hpkepb.HpkeAead_CHACHA20_POLY1305 {
		return fmt.Errorf("HPKE AEAD %s not supported", aead)
	}
	return nil
}
