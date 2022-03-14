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
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature/subtle"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtECDSAVerifierKeyVersion = 0
	jwtECDSAVerifierTypeURL    = "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"
	jwtECDSAEncoding           = "IEEE_P1363"
)

var (
	errECDSAInvalidAlgorithm       = errors.New("invalid algorithm")
	errECDSAVerifierNotImplemented = errors.New("not supported on verifier key manager")
)

// jwtECDSAVerifierKeyManager implements the KeyManager interface
// for JWT Verifier using the 'ES256', 'ES384', and 'ES512' JWA algorithm.
type jwtECDSAVerifierKeyManager struct{}

var _ registry.KeyManager = (*jwtECDSAVerifierKeyManager)(nil)

type ecdsaParams struct {
	Curve string
	Hash  string
}

var esAlgToParams = map[jepb.JwtEcdsaAlgorithm]ecdsaParams{
	jepb.JwtEcdsaAlgorithm_ES256: {Curve: "NIST_P256", Hash: "SHA256"},
	jepb.JwtEcdsaAlgorithm_ES384: {Curve: "NIST_P384", Hash: "SHA384"},
	jepb.JwtEcdsaAlgorithm_ES512: {Curve: "NIST_P521", Hash: "SHA512"},
}

func (km *jwtECDSAVerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if serializedKey == nil || len(serializedKey) == 0 {
		return nil, fmt.Errorf("invalid key")
	}
	pubKey := &jepb.JwtEcdsaPublicKey{}
	if err := proto.Unmarshal(serializedKey, pubKey); err != nil {
		return nil, err
	}
	if err := keyset.ValidateKeyVersion(pubKey.Version, jwtECDSAVerifierKeyVersion); err != nil {
		return nil, fmt.Errorf("invalid key: %v", err)
	}
	params, ok := esAlgToParams[pubKey.GetAlgorithm()]
	if !ok {
		return nil, errECDSAInvalidAlgorithm
	}
	tv, err := subtle.NewECDSAVerifier(params.Hash, params.Curve, jwtECDSAEncoding, pubKey.GetX(), pubKey.GetY())
	if err != nil {
		return nil, err
	}
	return newVerifierWithKID(tv, pubKey.GetAlgorithm().String(), ecdsaCustomKID(pubKey))
}

func (km *jwtECDSAVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errECDSAVerifierNotImplemented
}

func (km *jwtECDSAVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errECDSAVerifierNotImplemented
}

func (km *jwtECDSAVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == jwtECDSAVerifierTypeURL
}

func (km *jwtECDSAVerifierKeyManager) TypeURL() string {
	return jwtECDSAVerifierTypeURL
}

func ecdsaCustomKID(pk *jepb.JwtEcdsaPublicKey) *string {
	if pk.GetCustomKid() == nil {
		return nil
	}
	k := pk.GetCustomKid().GetValue()
	return &k
}
