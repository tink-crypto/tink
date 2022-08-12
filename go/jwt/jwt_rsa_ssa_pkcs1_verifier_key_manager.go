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
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/keyset"
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtRSVerifierKeyVersion = 0
	jwtRSVerifierTypeURL    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"
)

var (
	errJWTRSVerifierNotImplemented = errors.New("not supported on verifier key manager")
)

// jwtRSVerifierKeyManager implements the KeyManager interface
// for JWT Verifier using the 'RS256', 'RS384', and 'RS512' JSON Web Algorithms (JWA).
type jwtRSVerifierKeyManager struct{}

var _ registry.KeyManager = (*jwtRSVerifierKeyManager)(nil)

// adding to this map will automatically add to the list of
// "accepted" algorithms that will construct valid primitives.
var validRSAlgToHash = map[jrsppb.JwtRsaSsaPkcs1Algorithm]string{
	jrsppb.JwtRsaSsaPkcs1Algorithm_RS256: "SHA256",
	jrsppb.JwtRsaSsaPkcs1Algorithm_RS384: "SHA384",
	jrsppb.JwtRsaSsaPkcs1Algorithm_RS512: "SHA512",
}

func (km *jwtRSVerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if serializedKey == nil || len(serializedKey) == 0 {
		return nil, fmt.Errorf("invalid key")
	}
	pubKey := &jrsppb.JwtRsaSsaPkcs1PublicKey{}
	if err := proto.Unmarshal(serializedKey, pubKey); err != nil {
		return nil, err
	}
	if err := validateRSPublicKey(pubKey); err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(pubKey.GetE())
	if !e.IsInt64() {
		return nil, fmt.Errorf("public exponent can't fit in a 64 bit integer")
	}
	rsaPubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(pubKey.GetN()),
		E: int(e.Int64()),
	}
	v, err := signature.New_RSA_SSA_PKCS1_Verifier(validRSAlgToHash[pubKey.GetAlgorithm()], rsaPubKey)
	if err != nil {
		return nil, err
	}
	return newVerifierWithKID(v, pubKey.GetAlgorithm().String(), rsCustomKID(pubKey))
}

func (km *jwtRSVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errJWTRSVerifierNotImplemented
}

func (km *jwtRSVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errJWTRSVerifierNotImplemented
}

func (km *jwtRSVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == jwtRSVerifierTypeURL
}

func (km *jwtRSVerifierKeyManager) TypeURL() string {
	return jwtRSVerifierTypeURL
}

func validateRSPublicKey(pubKey *jrsppb.JwtRsaSsaPkcs1PublicKey) error {
	if pubKey == nil {
		return fmt.Errorf("nil public key")
	}
	if err := keyset.ValidateKeyVersion(pubKey.Version, jwtRSVerifierKeyVersion); err != nil {
		return err
	}
	if _, ok := validRSAlgToHash[pubKey.GetAlgorithm()]; !ok {
		return fmt.Errorf("invalid algorithm")
	}
	e := new(big.Int).SetBytes(pubKey.GetE())
	if !e.IsInt64() {
		return fmt.Errorf("public exponent can't fit in a 64 bit integer")
	}
	if err := signature.RSAValidPublicExponent(int(e.Int64())); err != nil {
		return err
	}
	return signature.RSAValidModulusSizeInBits(new(big.Int).SetBytes(pubKey.GetN()).BitLen())
}

func rsCustomKID(pk *jrsppb.JwtRsaSsaPkcs1PublicKey) *string {
	// nil is an acceptable value for a custom kid.
	if pk.GetCustomKid() == nil {
		return nil
	}
	k := pk.GetCustomKid().GetValue()
	return &k
}
