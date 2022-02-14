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

package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	subtlesign "github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtECDSASignerKeyVersion = 0
	jwtECDSASignerTypeURL    = "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"
)

var (
	errECDSAInvalidKey       = errors.New("invalid JwtEcdsaPrivateKey key")
	errECDSAInvalidKeyFormat = errors.New("invalid key format")
)

// jwtECDSASignerKeyManager implements the KeyManager interface
// for JWT Signing using the 'ES256', 'ES384', and 'ES512' JWA algorithm.
type jwtECDSASignerKeyManager struct{}

var _ registry.PrivateKeyManager = (*jwtECDSASignerKeyManager)(nil)

func (km *jwtECDSASignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if serializedKey == nil {
		return nil, errECDSAInvalidKey
	}
	privKey := &jepb.JwtEcdsaPrivateKey{}
	if err := proto.Unmarshal(serializedKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtEcdsaPrivateKey: %v", err)
	}
	params, err := km.validateKey(privKey)
	if err != nil {
		return nil, err
	}
	ts, err := subtlesign.NewECDSASigner(params.Hash, params.Curve, jwtECDSAEncoding, privKey.GetKeyValue())
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSASigner: %v", err)
	}
	pubKey := privKey.GetPublicKey()
	var kid *string = nil
	if pubKey.GetCustomKid() != nil {
		k := pubKey.GetCustomKid().GetValue()
		kid = &k
	}
	return newSignerWithKID(ts, pubKey.GetAlgorithm().String(), kid)
}

func (km *jwtECDSASignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if serializedKeyFormat == nil {
		return nil, errECDSAInvalidKeyFormat
	}
	keyFormat := &jepb.JwtEcdsaKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtEcdsaKeyFormat: %v", err)
	}
	params, ok := esAlgToParams[keyFormat.GetAlgorithm()]
	if !ok {
		return nil, errECDSAInvalidAlgorithm
	}
	k, err := ecdsa.GenerateKey(subtle.GetCurve(params.Curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	return &jepb.JwtEcdsaPrivateKey{
		Version: jwtECDSASignerKeyVersion,
		PublicKey: &jepb.JwtEcdsaPublicKey{
			Version:   jwtECDSASignerKeyVersion,
			Algorithm: keyFormat.GetAlgorithm(),
			X:         k.X.Bytes(),
			Y:         k.Y.Bytes(),
		},
		KeyValue: k.D.Bytes(),
	}, nil
}

func (km *jwtECDSASignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	if serializedKeyFormat == nil {
		return nil, errECDSAInvalidKeyFormat
	}
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JwtEcdsaPrivateKey: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtECDSASignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *jwtECDSASignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if serializedPrivKey == nil {
		return nil, errECDSAInvalidKey
	}
	privKey := &jepb.JwtEcdsaPrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtEcdsaPrivateKey: %v", err)
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtECDSAVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *jwtECDSASignerKeyManager) DoesSupport(typeURL string) bool {
	return jwtECDSASignerTypeURL == typeURL
}

func (km *jwtECDSASignerKeyManager) TypeURL() string {
	return jwtECDSASignerTypeURL
}

func (km *jwtECDSASignerKeyManager) validateKey(key *jepb.JwtEcdsaPrivateKey) (ecdsaParams, error) {
	if err := keyset.ValidateKeyVersion(key.Version, jwtECDSASignerKeyVersion); err != nil {
		return ecdsaParams{}, fmt.Errorf("invalid key version: %v", err)
	}
	if key.GetPublicKey() == nil {
		return ecdsaParams{}, fmt.Errorf("no public key in JwtEcdsaPrivateKey")
	}
	params, ok := esAlgToParams[key.GetPublicKey().GetAlgorithm()]
	if !ok {
		return ecdsaParams{}, errECDSAInvalidAlgorithm
	}
	return params, nil
}
