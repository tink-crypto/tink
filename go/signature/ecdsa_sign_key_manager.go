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

package signature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/golang/protobuf/proto"
	subtleSignature "github.com/google/tink/go/subtle/signature"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/tink"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	// EcdsaSignKeyVersion is the maximum version of keys that this manager supports.
	EcdsaSignKeyVersion = 0

	// EcdsaSignTypeURL is the only type URL that this manager supports.
	EcdsaSignTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

// common errors
var errInvalidEcdsaSignKey = fmt.Errorf("ecdsa_sign_key_manager: invalid key")
var errInvalidEcdsaSignKeyFormat = fmt.Errorf("ecdsa_sign_key_manager: invalid key format")

// EcdsaSignKeyManager is an implementation of KeyManager interface.
// It generates new EcdsaPrivateKeys and produces new instances of EcdsaSign subtle.
type EcdsaSignKeyManager struct{}

// Assert that EcdsaSignKeyManager implements the PrivateKeyManager interface.
var _ tink.PrivateKeyManager = (*EcdsaSignKeyManager)(nil)

// NewEcdsaSignKeyManager creates a new EcdsaSignKeyManager.
func NewEcdsaSignKeyManager() *EcdsaSignKeyManager {
	return new(EcdsaSignKeyManager)
}

// Primitive creates an EcdsaSign subtle for the given serialized EcdsaPrivateKey proto.
func (km *EcdsaSignKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidEcdsaSignKey
	}
	key := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidEcdsaSignKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash, curve, encoding := GetEcdsaParamNames(key.PublicKey.Params)
	ret, err := subtleSignature.NewEcdsaSign(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_sign_key_manager: %s", err)
	}
	return ret, nil
}

// NewKey creates a new EcdsaPrivateKey according to specification the given serialized EcdsaKeyFormat.
func (km *EcdsaSignKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidEcdsaSignKeyFormat
	}
	keyFormat := new(ecdsapb.EcdsaKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_sign_key_manager: invalid key format: %s", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_sign_key_manager: %s", err)
	}
	// generate key
	params := keyFormat.Params
	curve := tink.GetCurveName(params.Curve)
	tmpKey, err := ecdsa.GenerateKey(subtle.GetCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate ECDSA key: %s", err)
	}

	keyValue := tmpKey.D.Bytes()
	pub := NewEcdsaPublicKey(EcdsaSignKeyVersion, params, tmpKey.X.Bytes(), tmpKey.Y.Bytes())
	priv := NewEcdsaPrivateKey(EcdsaSignKeyVersion, pub, keyValue)
	return priv, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized EcdsaKeyFormat. It should be used solely by the key management API.
func (km *EcdsaSignKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidEcdsaSignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         EcdsaSignTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *EcdsaSignKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidEcdsaSignKey
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidEcdsaSignKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         EcdsaVerifyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *EcdsaSignKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == EcdsaSignTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *EcdsaSignKeyManager) TypeURL() string {
	return EcdsaSignTypeURL
}

// validateKey validates the given EcdsaPrivateKey.
func (km *EcdsaSignKeyManager) validateKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := tink.ValidateVersion(key.Version, EcdsaSignKeyVersion); err != nil {
		return fmt.Errorf("ecdsa_sign_key_manager: %s", err)
	}
	hash, curve, encoding := GetEcdsaParamNames(key.PublicKey.Params)
	return subtleSignature.ValidateEcdsaParams(hash, curve, encoding)
}

// validateKeyFormat validates the given EcdsaKeyFormat.
func (km *EcdsaSignKeyManager) validateKeyFormat(format *ecdsapb.EcdsaKeyFormat) error {
	hash, curve, encoding := GetEcdsaParamNames(format.Params)
	return subtleSignature.ValidateEcdsaParams(hash, curve, encoding)
}
