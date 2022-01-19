// Copyright 2018 Google LLC
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
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	subtleSignature "github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	ecdsaSignerKeyVersion = 0
	ecdsaSignerTypeURL    = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

// common errors
var errInvalidECDSASignKey = errors.New("ecdsa_signer_key_manager: invalid key")
var errInvalidECDSASignKeyFormat = errors.New("ecdsa_signer_key_manager: invalid key format")

// ecdsaSignerKeyManager is an implementation of KeyManager interface.
// It generates new ECDSAPrivateKeys and produces new instances of ECDSASign subtle.
type ecdsaSignerKeyManager struct{}

// Primitive creates an ECDSASign subtle for the given serialized ECDSAPrivateKey proto.
func (km *ecdsaSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDSASignKey
	}
	key := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidECDSASignKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash, curve, encoding := getECDSAParamNames(key.PublicKey.Params)
	ret, err := subtleSignature.NewECDSASigner(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: %s", err)
	}
	return ret, nil
}

// NewKey creates a new ECDSAPrivateKey according to specification the given serialized ECDSAKeyFormat.
func (km *ecdsaSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDSASignKeyFormat
	}
	keyFormat := new(ecdsapb.EcdsaKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: invalid proto: %s", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: invalid key format: %s", err)
	}
	// generate key
	params := keyFormat.Params
	curve := commonpb.EllipticCurveType_name[int32(params.Curve)]
	tmpKey, err := ecdsa.GenerateKey(subtle.GetCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_signer_key_manager: cannot generate ECDSA key: %s", err)
	}

	keyValue := tmpKey.D.Bytes()
	pub := newECDSAPublicKey(ecdsaSignerKeyVersion, params, tmpKey.X.Bytes(), tmpKey.Y.Bytes())
	priv := newECDSAPrivateKey(ecdsaSignerKeyVersion, pub, keyValue)
	return priv, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ECDSAKeyFormat. It should be used solely by the key management API.
func (km *ecdsaSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidECDSASignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         ecdsaSignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *ecdsaSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidECDSASignKey
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDSASignKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         ecdsaVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdsaSignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdsaSignerTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdsaSignerKeyManager) TypeURL() string {
	return ecdsaSignerTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *ecdsaSignerKeyManager) validateKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, ecdsaSignerKeyVersion); err != nil {
		return fmt.Errorf("ecdsa_signer_key_manager: invalid key: %s", err)
	}
	hash, curve, encoding := getECDSAParamNames(key.PublicKey.Params)
	return subtleSignature.ValidateECDSAParams(hash, curve, encoding)
}

// validateKeyFormat validates the given ECDSAKeyFormat.
func (km *ecdsaSignerKeyManager) validateKeyFormat(format *ecdsapb.EcdsaKeyFormat) error {
	hash, curve, encoding := getECDSAParamNames(format.Params)
	return subtleSignature.ValidateECDSAParams(hash, curve, encoding)
}
