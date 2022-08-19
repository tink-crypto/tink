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
	"github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/keyset"
	jrsppb "github.com/google/tink/go/proto/jwt_rsa_ssa_pss_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtPSSignerKeyVersion = 0
	jwtPSSignerTypeURL    = "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey"
)

var (
	errPSInvalidPrivateKey = errors.New("invalid JwtRsaSsaPssPrivateKey")
	errPSInvalidKeyFormat  = errors.New("invalid RSA SSA PSS key format")
)

// jwtPSSignerKeyManager implements the KeyManager interface
// for JWT Signing using the 'PS256', 'PS384', and 'PS512' JWA algorithm.
type jwtPSSignerKeyManager struct{}

// TODO(b/230489047): delete in diffbase once cross language tests are fixed
func newJWTPSSignerKeyManager() registry.KeyManager {
	return &jwtPSSignerKeyManager{}
}

var _ registry.PrivateKeyManager = (*jwtPSSignerKeyManager)(nil)

func (km *jwtPSSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if serializedKey == nil {
		return nil, fmt.Errorf("invalid JwtRsaSsaPSSPrivateKey")
	}
	privKey := &jrsppb.JwtRsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPssPrivateKey: %v", err)
	}
	if err := validatePSPrivateKey(privKey); err != nil {
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
			// in crypto/rsa `Qinv` is the "Chinese Remainder Theorem
			// coefficient q^(-1) mod p. Which is `GetCrt` in the tink proto and not
			// the `CRTValues`.
			Qinv: bytesToBigInt(privKey.GetCrt()),
		},
	}
	algorithm := privKey.GetPublicKey().GetAlgorithm()
	signer, err := signature.New_RSA_SSA_PSS_Signer(validPSAlgToHash[algorithm], psAlgToSaltLen[algorithm], rsaPrivKey)
	if err != nil {
		return nil, err
	}
	return newSignerWithKID(signer, algorithm.String(), psCustomKID(privKey.GetPublicKey()))
}

func validatePSPrivateKey(privKey *jrsppb.JwtRsaSsaPssPrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.Version, jwtPSSignerKeyVersion); err != nil {
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
	if err := validatePSPublicKey(privKey.GetPublicKey()); err != nil {
		return err
	}
	// TODO(b/230489047): add a validation the key can actually sign.
	return nil
}

func (km *jwtPSSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errPSInvalidKeyFormat
	}
	keyFormat := &jrsppb.JwtRsaSsaPssKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPssKeyFormat: %v", err)
	}
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), jwtPSSignerKeyVersion); err != nil {
		return nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.GetModulusSizeInBits()))
	if err != nil {
		return nil, err
	}
	privKey := &jrsppb.JwtRsaSsaPssPrivateKey{
		Version: jwtPSSignerKeyVersion,
		PublicKey: &jrsppb.JwtRsaSsaPssPublicKey{
			Version:   jwtPSSignerKeyVersion,
			Algorithm: keyFormat.GetAlgorithm(),
			N:         rsaKey.PublicKey.N.Bytes(),
			E:         keyFormat.GetPublicExponent(),
		},
		D:  rsaKey.D.Bytes(),
		P:  rsaKey.Primes[0].Bytes(),
		Q:  rsaKey.Primes[1].Bytes(),
		Dp: rsaKey.Precomputed.Dp.Bytes(),
		Dq: rsaKey.Precomputed.Dq.Bytes(),
		// in crypto/rsa `Qinv` is the "Chinese Remainder Theorem
		// coefficient q^(-1) mod p. Which is `Crt` in the tink proto and not
		// the `CRTValues`.
		Crt: rsaKey.Precomputed.Qinv.Bytes(),
	}
	if err := validatePSPrivateKey(privKey); err != nil {
		return nil, err
	}
	return privKey, nil
}

func (km *jwtPSSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtPSSignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *jwtPSSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if serializedPrivKey == nil {
		return nil, errPSInvalidKeyFormat
	}
	privKey := &jrsppb.JwtRsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JwtRsaSsaPssPrivateKey: %v", err)
	}
	if err := validatePSPrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtPSVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *jwtPSSignerKeyManager) DoesSupport(typeURL string) bool {
	return jwtPSSignerTypeURL == typeURL
}

func (km *jwtPSSignerKeyManager) TypeURL() string {
	return jwtPSSignerTypeURL
}
