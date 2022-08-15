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
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pss_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtPSVerifierKeyVersion = 0
	jwtPSVerifierTypeURL    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey"
)

var errJWTPSVerifierNotImplemented = errors.New("not supported on verifier key manager")

// jwtPSVerifierKeyManager implements the KeyManager interface
// for JWT Verifier using the 'PS256', 'PS384', and 'PS512' JSON Web Algorithms (JWA).
type jwtPSVerifierKeyManager struct{}

var _ registry.KeyManager = (*jwtPSVerifierKeyManager)(nil)

// adding to this map will automatically add to the list of
// "accepted" algorithms that will construct valid primitives.
var validPSAlgToHash = map[jrsppb.JwtRsaSsaPssAlgorithm]string{
	jrsppb.JwtRsaSsaPssAlgorithm_PS256: "SHA256",
	jrsppb.JwtRsaSsaPssAlgorithm_PS384: "SHA384",
	jrsppb.JwtRsaSsaPssAlgorithm_PS512: "SHA512",
}

var psAlgToSaltLen = map[jrsppb.JwtRsaSsaPssAlgorithm]int{
	jrsppb.JwtRsaSsaPssAlgorithm_PS256: 32,
	jrsppb.JwtRsaSsaPssAlgorithm_PS384: 48,
	jrsppb.JwtRsaSsaPssAlgorithm_PS512: 64,
}

func (km *jwtPSVerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if serializedKey == nil || len(serializedKey) == 0 {
		return nil, fmt.Errorf("invalid key")
	}
	pubKey := &jrsppb.JwtRsaSsaPssPublicKey{}
	if err := proto.Unmarshal(serializedKey, pubKey); err != nil {
		return nil, err
	}
	if err := validatePSPublicKey(pubKey); err != nil {
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
	algorithm := pubKey.GetAlgorithm()
	v, err := signature.New_RSA_SSA_PSS_Verifier(validPSAlgToHash[algorithm], psAlgToSaltLen[algorithm], rsaPubKey)
	if err != nil {
		return nil, err
	}
	return newVerifierWithKID(v, algorithm.String(), psCustomKID(pubKey))
}

func (km *jwtPSVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errJWTPSVerifierNotImplemented
}

func (km *jwtPSVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errJWTPSVerifierNotImplemented
}

func (km *jwtPSVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == jwtPSVerifierTypeURL
}

func (km *jwtPSVerifierKeyManager) TypeURL() string {
	return jwtPSVerifierTypeURL
}

func validatePSPublicKey(pubKey *jrsppb.JwtRsaSsaPssPublicKey) error {
	if pubKey == nil {
		return fmt.Errorf("nil public key")
	}
	if err := keyset.ValidateKeyVersion(pubKey.Version, jwtPSVerifierKeyVersion); err != nil {
		return err
	}
	if _, ok := validPSAlgToHash[pubKey.GetAlgorithm()]; !ok {
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

func psCustomKID(pk *jrsppb.JwtRsaSsaPssPublicKey) *string {
	// nil is an acceptable value for a custom kid.
	if pk.GetCustomKid() == nil {
		return nil
	}
	k := pk.GetCustomKid().GetValue()
	return &k
}
