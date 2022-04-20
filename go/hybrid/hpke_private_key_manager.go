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

package hybrid

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid/internal/hpke"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle"
	hpkepb "github.com/google/tink/go/proto/hpke_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	// maxSupportedHPKEPrivateKeyVersion is the max supported private key
	// version. It must be incremented when support for new versions are
	// implemented.
	maxSupportedHPKEPrivateKeyVersion uint32 = 0
	hpkePrivateKeyTypeURL                    = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"
)

var (
	errInvalidHPKEPrivateKey       = errors.New("invalid HPKE private key")
	errInvalidHPKEPrivateKeyFormat = errors.New("invalid HPKE private key format")
)

// hpkePrivateKeyManager implements the KeyManager interface for HybridDecrypt.
type hpkePrivateKeyManager struct{}

var _ registry.PrivateKeyManager = (*hpkePrivateKeyManager)(nil)

func (p *hpkePrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidHPKEPrivateKey
	}
	key := new(hpkepb.HpkePrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidHPKEPrivateKey
	}
	if err := keyset.ValidateKeyVersion(key.GetVersion(), maxSupportedHPKEPrivateKeyVersion); err != nil {
		return nil, err
	}
	return hpke.NewDecrypt(key)
}

// NewKey returns a set of private and public keys of key version 0.
func (p *hpkePrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHPKEPrivateKeyFormat
	}
	keyFormat := new(hpkepb.HpkeKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHPKEPrivateKeyFormat
	}
	if err := validateKeyFormat(keyFormat); err != nil {
		return nil, err
	}

	privKeyBytes, err := subtle.GeneratePrivateKeyX25519()
	if err != nil {
		return nil, fmt.Errorf("generate X25519 private key: %v", err)
	}
	pubKeyBytes, err := subtle.PublicFromPrivateX25519(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("get X25519 public key from private key: %v", err)
	}

	return &hpkepb.HpkePrivateKey{
		Version: 0,
		PublicKey: &hpkepb.HpkePublicKey{
			Version:   0,
			Params:    keyFormat.GetParams(),
			PublicKey: pubKeyBytes,
		},
		PrivateKey: privKeyBytes,
	}, nil
}

func (p *hpkePrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := p.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         hpkePrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (p *hpkePrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(hpkepb.HpkePrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidHPKEPrivateKey
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, errInvalidHPKEPrivateKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         hpkePublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (p *hpkePrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hpkePrivateKeyTypeURL
}

func (p *hpkePrivateKeyManager) TypeURL() string {
	return hpkePrivateKeyTypeURL
}

func validateKeyFormat(kf *hpkepb.HpkeKeyFormat) error {
	params := kf.GetParams()
	kem, kdf, aead := params.GetKem(), params.GetKdf(), params.GetAead()
	if kem != hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256 ||
		kdf != hpkepb.HpkeKdf_HKDF_SHA256 ||
		(aead != hpkepb.HpkeAead_AES_128_GCM && aead != hpkepb.HpkeAead_AES_256_GCM && aead != hpkepb.HpkeAead_CHACHA20_POLY1305) {
		return errInvalidHPKEPrivateKeyFormat
	}
	return nil
}
