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

package hybrid

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	eahpb "github.com/google/tink/go/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	eciesAEADHKDFPublicKeyKeyVersion = 0

	eciesAEADHKDFPublicKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"
)

// common errors
var errInvalidECIESAEADHKDFPublicKeyKey = fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key")
var errInvalidECIESAEADHKDFPublicKeyKeyFormat = fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key format")

// eciesAEADHKDFPublicKeyKeyManager is an implementation of KeyManager interface.
// It generates new ECIESAEADHKDFPublicKeyKey keys and produces new instances of ECIESAEADHKDFPublicKey subtle.
type eciesAEADHKDFPublicKeyKeyManager struct{}

// Assert that eciesAEADHKDFPublicKeyKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*eciesAEADHKDFPublicKeyKeyManager)(nil)

// newECIESAEADHKDFPublicKeyKeyManager creates a new aesGcmKeyManager.
func newECIESAEADHKDFPublicKeyKeyManager() *eciesAEADHKDFPublicKeyKeyManager {
	return new(eciesAEADHKDFPublicKeyKeyManager)
}

// Primitive creates an ECIESAEADHKDFPublicKey subtle for the given serialized ECIESAEADHKDFPublicKey proto.
func (km *eciesAEADHKDFPublicKeyKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECIESAEADHKDFPublicKeyKey
	}
	key := new(eahpb.EciesAeadHkdfPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidECIESAEADHKDFPublicKeyKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, errInvalidECIESAEADHKDFPublicKeyKey
	}
	curve, err := subtle.GetCurve(key.Params.KemParams.CurveType.String())
	if err != nil {
		return nil, err
	}
	pub := subtle.ECPublicKey{
		Curve: curve,
		Point: subtle.ECPoint{
			X: new(big.Int).SetBytes(key.X),
			Y: new(big.Int).SetBytes(key.Y),
		},
	}
	rDem, err := newRegisterECIESAEADHKDFDemHelper(key.Params.DemParams.AeadDem)
	if err != nil {
		return nil, err
	}
	salt := key.Params.KemParams.HkdfSalt
	hash := key.Params.KemParams.HkdfHashType.String()
	ptFormat := key.Params.EcPointFormat.String()

	return subtle.NewECIESAEADHKDFHybridEncrypt(&pub, salt, hash, ptFormat, rDem)
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *eciesAEADHKDFPublicKeyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == eciesAEADHKDFPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *eciesAEADHKDFPublicKeyKeyManager) TypeURL() string {
	return eciesAEADHKDFPublicKeyTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *eciesAEADHKDFPublicKeyKeyManager) validateKey(key *eahpb.EciesAeadHkdfPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, eciesAEADHKDFPublicKeyKeyVersion); err != nil {
		return fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key: %s", err)
	}
	return checkECIESAEADHKDFParams(key.Params)
}

// NewKey is not implemented for public key manager.
func (km *eciesAEADHKDFPublicKeyKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("public key manager does not implement NewKey")
}

// NewKeyData is not implemented for public key manager.
func (km *eciesAEADHKDFPublicKeyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("public key manager does not implement NewKeyData")
}
