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

// Package hybrid provides subtle implementations of the HKDF and EC primitives.
package hybrid

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	subtle "github.com/google/tink/go/subtle/hybrid"
	eahpb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	eciesAeadHkdfPublicKeyKeyVersion = 0

	eciesAeadHkdfPublicKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"
)

// common errors
var errInvalidEciesAeadHkdfPublicKeyKey = fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key")
var errInvalidEciesAeadHkdfPublicKeyKeyFormat = fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key format")

// eciesAeadHkdfPublicKeyKeyManager is an implementation of KeyManager interface.
// It generates new EciesAeadHkdfPublicKeyKey keys and produces new instances of EciesAeadHkdfPublicKey subtle.
type eciesAeadHkdfPublicKeyKeyManager struct{}

// Assert that eciesAeadHkdfPublicKeyKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*eciesAeadHkdfPublicKeyKeyManager)(nil)

// newEciesAeadHkdfPublicKeyKeyManager creates a new aesGcmKeyManager.
func newEciesAeadHkdfPublicKeyKeyManager() *eciesAeadHkdfPublicKeyKeyManager {
	return new(eciesAeadHkdfPublicKeyKeyManager)
}

// Primitive creates an EciesAeadHkdfPublicKey subtle for the given serialized EciesAeadHkdfPublicKey proto.
func (km *eciesAeadHkdfPublicKeyKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidEciesAeadHkdfPublicKeyKey
	}
	key := new(eahpb.EciesAeadHkdfPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidEciesAeadHkdfPublicKeyKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, errInvalidEciesAeadHkdfPublicKeyKey
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
	rDem, err := newRegisterEciesAeadHkdfDemHelper(key.Params.DemParams.AeadDem)
	if err != nil {
		return nil, err
	}
	salt := key.Params.KemParams.HkdfSalt
	hash := key.Params.KemParams.HkdfHashType.String()
	ptFormat := key.Params.EcPointFormat.String()

	return subtle.NewEciesAeadHkdfHybridEncrypt(&pub, salt, hash, ptFormat, rDem)
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *eciesAeadHkdfPublicKeyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == eciesAeadHkdfPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *eciesAeadHkdfPublicKeyKeyManager) TypeURL() string {
	return eciesAeadHkdfPublicKeyTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *eciesAeadHkdfPublicKeyKeyManager) validateKey(key *eahpb.EciesAeadHkdfPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, eciesAeadHkdfPublicKeyKeyVersion); err != nil {
		return fmt.Errorf("ecies_aead_hkdf_public_key_manager: invalid key: %s", err)
	}
	return checkEciesAeadHkdfParams(key.Params)
}

// NewKey is not implemented for public key manager.
func (km *eciesAeadHkdfPublicKeyKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("public key manager does not implement NewKey")
}

// NewKeyData is not implemented for public key manager.
func (km *eciesAeadHkdfPublicKeyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("public key manager does not implement NewKeyData")
}
