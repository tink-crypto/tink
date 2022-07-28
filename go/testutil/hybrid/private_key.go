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

// Package hybrid provides HybridEncrypt/Decrypt primitive-specific test
// utilities.
package hybrid

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	hpkepb "github.com/google/tink/go/proto/hpke_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	// HPKE key lengths from
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
	hpkeX25519HKDFSHA256PrivKeyLen = 32
	hpkeX25519HKDFSHA256PubKeyLen  = 32

	hpkePrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
)

// KeysetHandleFromSerializedPrivateKey returns a keyset handle containing a
// primary key that has the specified privKeyBytes and pubKeyBytes and matches
// template.
//
// Supported templates include:
//   - DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template,
//     which requires privKeyBytes and pubKeyBytes to be the KEM-encoding of the
//     private and public key, respectively, i.e. SerializePrivateKey and
//     SerializePublicKey in
//     https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1.
func KeysetHandleFromSerializedPrivateKey(privKeyBytes, pubKeyBytes []byte, template *tinkpb.KeyTemplate) (*keyset.Handle, error) {
	params, err := hpkeParamsFromTemplate(template)
	if err != nil {
		return nil, fmt.Errorf("failed to verify key template: %v", err)
	}
	if len(privKeyBytes) != hpkeX25519HKDFSHA256PrivKeyLen {
		return nil, fmt.Errorf("privKeyBytes length is %d but should be %d", len(privKeyBytes), hpkeX25519HKDFSHA256PrivKeyLen)
	}
	if len(pubKeyBytes) != hpkeX25519HKDFSHA256PubKeyLen {
		return nil, fmt.Errorf("pubKeyBytes length is %d but should be %d", len(pubKeyBytes), hpkeX25519HKDFSHA256PubKeyLen)
	}

	privKey := &hpkepb.HpkePrivateKey{
		Version:    0,
		PrivateKey: privKeyBytes,
		PublicKey: &hpkepb.HpkePublicKey{
			Version:   0,
			Params:    params,
			PublicKey: pubKeyBytes,
		},
	}
	serializedPrivKey, err := proto.Marshal(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HpkePrivateKey %v: %v", privKey, err)
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         hpkePrivateKeyTypeURL,
					Value:           serializedPrivKey,
					KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
				},
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	return insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
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
