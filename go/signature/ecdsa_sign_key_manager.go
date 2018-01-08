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

package signature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/golang/protobuf/proto"
	subtleEcdsa "github.com/google/tink/go/subtle/ecdsa"
	"github.com/google/tink/go/subtle/subtleutil"
	"github.com/google/tink/go/tink/tink"
	"github.com/google/tink/go/util/util"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	// Supported version
	ECDSA_SIGN_KEY_VERSION = 0

	// Supported type url
	ECDSA_SIGN_TYPE_URL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
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

// GetPrimitiveFromSerializedKey creates an EcdsaSign subtle for the given
// serialized EcdsaPrivateKey proto.
func (km *EcdsaSignKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidEcdsaSignKey
	}
	key := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidEcdsaSignKey
	}
	return km.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKey creates an EcdsaSign subtle for the given EcdsaPrivateKey proto.
func (km *EcdsaSignKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
	key, ok := m.(*ecdsapb.EcdsaPrivateKey)
	if !ok {
		return nil, errInvalidEcdsaSignKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash, curve, encoding := util.GetEcdsaParamNames(key.PublicKey.Params)
	ret, err := subtleEcdsa.NewEcdsaSign(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_sign_key_manager: %s", err)
	}
	return ret, nil
}

// NewKeyFromSerializedKeyFormat creates a new EcdsaPrivateKey according to specification
// the given serialized EcdsaKeyFormat.
func (km *EcdsaSignKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidEcdsaSignKeyFormat
	}
	keyFormat := new(ecdsapb.EcdsaKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_sign_key_manager: invalid key format: %s", err)
	}
	return km.NewKeyFromKeyFormat(keyFormat)
}

// NewKeyFromKeyFormat creates a new key according to specification in the
// given EcdsaKeyFormat.
func (km *EcdsaSignKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
	format, ok := m.(*ecdsapb.EcdsaKeyFormat)
	if !ok {
		return nil, errInvalidEcdsaSignKeyFormat
	}
	if err := km.validateKeyFormat(format); err != nil {
		return nil, fmt.Errorf("ecdsa_sign_key_manager: %s", err)
	}
	// generate key
	params := format.Params
	curve := util.GetCurveName(params.Curve)
	tmpKey, _ := ecdsa.GenerateKey(subtleutil.GetCurve(curve), rand.Reader)
	keyValue := tmpKey.D.Bytes()
	pub := util.NewEcdsaPublicKey(ECDSA_SIGN_KEY_VERSION, params, tmpKey.X.Bytes(), tmpKey.Y.Bytes())
	priv := util.NewEcdsaPrivateKey(ECDSA_SIGN_KEY_VERSION, pub, keyValue)
	return priv, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized EcdsaKeyFormat. It should be used solely by the key management API.
func (km *EcdsaSignKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKeyFromSerializedKeyFormat(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidEcdsaSignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         ECDSA_SIGN_TYPE_URL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// GetPublicKeyData extracts the public key data from the private key.
func (km *EcdsaSignKeyManager) GetPublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidEcdsaSignKey
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidEcdsaSignKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         ECDSA_VERIFY_TYPE_URL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (_ *EcdsaSignKeyManager) DoesSupport(typeUrl string) bool {
	return typeUrl == ECDSA_SIGN_TYPE_URL
}

// GetKeyType returns the key type of keys managed by this key manager.
func (_ *EcdsaSignKeyManager) GetKeyType() string {
	return ECDSA_SIGN_TYPE_URL
}

// validateKey validates the given EcdsaPrivateKey.
func (_ *EcdsaSignKeyManager) validateKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := util.ValidateVersion(key.Version, ECDSA_SIGN_KEY_VERSION); err != nil {
		return fmt.Errorf("ecdsa_sign_key_manager: %s", err)
	}
	hash, curve, encoding := util.GetEcdsaParamNames(key.PublicKey.Params)
	return subtleEcdsa.ValidateParams(hash, curve, encoding)
}

// validateKeyFormat validates the given EcdsaKeyFormat.
func (_ *EcdsaSignKeyManager) validateKeyFormat(format *ecdsapb.EcdsaKeyFormat) error {
	hash, curve, encoding := util.GetEcdsaParamNames(format.Params)
	return subtleEcdsa.ValidateParams(hash, curve, encoding)
}
