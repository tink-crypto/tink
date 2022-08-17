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
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	internal "github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/keyset"
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtRSSignerKeyVersion = 0
	jwtRSSignerTypeURL    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey"
)

var (
	errRSInvalidPrivateKey = errors.New("invalid JwtRsaSsaPkcs1PrivateKey")
	errRSInvalidKeyFormat  = errors.New("invalid RSA SSA PKCS1 key format")
)

// jwtRSSignerKeyManager implements the KeyManager interface
// for JWT Signing using the 'RS256', 'RS384', and 'RS512' JWA algorithm.
type jwtRSSignerKeyManager struct{}

// TODO(b/230489047): delete in diffbase once cross language tests are fixed
func newjwtRSSignerKeyManager() registry.KeyManager {
	return &jwtRSSignerKeyManager{}
}

var _ registry.PrivateKeyManager = (*jwtRSSignerKeyManager)(nil)

func bytesToBigInt(v []byte) *big.Int {
	return new(big.Int).SetBytes(v)
}

func (km *jwtRSSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if serializedKey == nil {
		return nil, fmt.Errorf("invalid JwtRsaSsaPkcs1PrivateKey")
	}
	privKey := &jrsppb.JwtRsaSsaPkcs1PrivateKey{}
	if err := proto.Unmarshal(serializedKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal RsaSsaPkcs1PrivateKey: %v", err)
	}
	if err := validateRSPrivateKey(privKey); err != nil {
		return nil, err
	}
	rsaPrivKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: bytesToBigInt(privKey.GetPublicKey().GetN()),
			E: int(bytesToBigInt(privKey.GetPublicKey().GetE()).Int64()),
		},
		D: bytesToBigInt(privKey.GetD()),
		Primes: []*big.Int{
			bytesToBigInt(privKey.GetP()),
			bytesToBigInt(privKey.GetQ()),
		},
		Precomputed: rsa.PrecomputedValues{
			Dp: bytesToBigInt(privKey.GetDp()),
			Dq: bytesToBigInt(privKey.GetDq()),
			// in crypto/rsa `GetCrt()` returns the "Chinese Remainder Theorem
			// coefficient q^(-1) mod p. Which is `Qinv` in the tink proto and not
			// the `CRTValues`.
			Qinv: bytesToBigInt(privKey.GetCrt()),
		},
	}
	alg := privKey.GetPublicKey().GetAlgorithm()
	signer, err := internal.New_RSA_SSA_PKCS1_Signer(validRSAlgToHash[alg], rsaPrivKey)
	if err != nil {
		return nil, err
	}
	return newSignerWithKID(signer, alg.String(), rsCustomKID(privKey.GetPublicKey()))
}

func validateRSPrivateKey(privKey *jrsppb.JwtRsaSsaPkcs1PrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.Version, jwtRSSignerKeyVersion); err != nil {
		return err
	}
	if privKey.GetD() == nil ||
		len(privKey.GetPublicKey().GetN()) == 0 ||
		len(privKey.GetPublicKey().GetE()) == 0 ||
		privKey.GetP() == nil ||
		privKey.GetQ() == nil ||
		privKey.GetDp() == nil ||
		privKey.GetDq() == nil ||
		privKey.GetCrt() == nil {
		return fmt.Errorf("invalid private key")
	}
	if err := validateRSPublicKey(privKey.GetPublicKey()); err != nil {
		return err
	}
	// TODO(b/230489047): add a validation the key can actually sign.
	return nil
}

func (km *jwtRSSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errRSInvalidKeyFormat
	}
	keyFormat := &jrsppb.JwtRsaSsaPkcs1KeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPkcs1KeyFormat: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), jwtRSSignerKeyVersion); err != nil {
		return nil, err
	}
	if keyFormat.GetVersion() != jwtRSSignerKeyVersion {
		return nil, fmt.Errorf("invalid key format version: %d", keyFormat.GetVersion())
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.GetModulusSizeInBits()))
	if err != nil {
		return nil, err
	}
	privKey := &jrsppb.JwtRsaSsaPkcs1PrivateKey{
		Version: jwtRSSignerKeyVersion,
		PublicKey: &jrsppb.JwtRsaSsaPkcs1PublicKey{
			Version:   jwtRSSignerKeyVersion,
			Algorithm: keyFormat.GetAlgorithm(),
			N:         rsaKey.PublicKey.N.Bytes(),
			E:         keyFormat.GetPublicExponent(),
		},
		D:  rsaKey.D.Bytes(),
		P:  rsaKey.Primes[0].Bytes(),
		Q:  rsaKey.Primes[1].Bytes(),
		Dp: rsaKey.Precomputed.Dp.Bytes(),
		Dq: rsaKey.Precomputed.Dq.Bytes(),
		// in crypto/rsa `GetCrt()` returns the "Chinese Remainder Theorem
		// coefficient q^(-1) mod p. Which is `Qinv` in the tink proto and not
		// the `CRTValues`.
		Crt: rsaKey.Precomputed.Qinv.Bytes(),
	}
	if err := validateRSPrivateKey(privKey); err != nil {
		return nil, err
	}
	return privKey, nil
}

func (km *jwtRSSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtRSSignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *jwtRSSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if serializedPrivKey == nil {
		return nil, errRSInvalidKeyFormat
	}
	privKey := &jrsppb.JwtRsaSsaPkcs1PrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPkcs1PrivateKey: %v", err)
	}
	if err := validateRSPrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtRSVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *jwtRSSignerKeyManager) DoesSupport(typeURL string) bool {
	return jwtRSSignerTypeURL == typeURL
}

func (km *jwtRSSignerKeyManager) TypeURL() string {
	return jwtRSSignerTypeURL
}
