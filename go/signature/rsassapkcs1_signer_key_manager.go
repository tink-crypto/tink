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

package signature

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
	rsassapkcs1pb "github.com/google/tink/go/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	rsaSSAPKCS1SignerKeyVersion = 0
	rsaSSAPKCS1SignerTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
)

var (
	errInvalidRSASSAPKCS1SignKey       = errors.New("rsassapkcs1_signer_key_manager: invalid key")
	errInvalidRSASSAPKCS1SignKeyFormat = errors.New("rsassapkcs1_signer_key_manager: invalid key format")
)

type rsaSSAPKCS1SignerKeyManager struct{}

var _ registry.PrivateKeyManager = (*rsaSSAPKCS1SignerKeyManager)(nil)

func (km *rsaSSAPKCS1SignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if false {
		return nil, errInvalidRSASSAPKCS1SignKey
	}
	key := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := validateRSAPKCS1PrivateKey(key); err != nil {
		return nil, err
	}

	privKey := &rsa.PrivateKey{
		D: bytesToBigInt(key.GetD()),
		PublicKey: rsa.PublicKey{
			N: bytesToBigInt(key.GetPublicKey().GetN()),
			E: int(bytesToBigInt(key.GetPublicKey().GetE()).Int64()),
		},
		Primes: []*big.Int{
			bytesToBigInt(key.GetP()),
			bytesToBigInt(key.GetQ()),
		},
	}
	// Instead of extracting Dp, Dq, and Qinv values from the key proto,
	// the values must be computed by the Go library.
	//
	// See https://pkg.go.dev/crypto/rsa#PrivateKey.
	privKey.Precompute()

	h := hashName(key.GetPublicKey().GetParams().GetHashType())
	if err := internal.Validate_RSA_SSA_PKCS1(h, privKey); err != nil {
		return nil, err
	}
	return internal.New_RSA_SSA_PKCS1_Signer(h, privKey)
}

func validateRSAPKCS1PrivateKey(privKey *rsassapkcs1pb.RsaSsaPkcs1PrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.Version, rsaSSAPKCS1SignerKeyVersion); err != nil {
		return err
	}
	if len(privKey.GetD()) == 0 ||
		len(privKey.GetPublicKey().GetN()) == 0 ||
		len(privKey.GetPublicKey().GetE()) == 0 ||
		len(privKey.GetP()) == 0 ||
		len(privKey.GetQ()) == 0 ||
		len(privKey.GetDp()) == 0 ||
		len(privKey.GetDq()) == 0 ||
		len(privKey.GetCrt()) == 0 {
		return errInvalidRSASSAPKCS1SignKey
	}
	return validateRSAPKCS1PublicKey(privKey.GetPublicKey())
}

func (km *rsaSSAPKCS1SignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidRSASSAPKCS1SignKeyFormat
	}
	keyFormat := &rsassapkcs1pb.RsaSsaPkcs1KeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, err
	}
	if err := validateRSAPubKeyParams(
		keyFormat.GetParams().GetHashType(),
		int(keyFormat.GetModulusSizeInBits()),
		keyFormat.GetPublicExponent()); err != nil {
		return nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, int(keyFormat.ModulusSizeInBits))
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %s", err)
	}
	pubKey := &rsassapkcs1pb.RsaSsaPkcs1PublicKey{
		Version: rsaSSAPKCS1SignerKeyVersion,
		Params: &rsassapkcs1pb.RsaSsaPkcs1Params{
			HashType: keyFormat.Params.HashType,
		},
		N: rsaKey.PublicKey.N.Bytes(),
		E: big.NewInt(int64(rsaKey.PublicKey.E)).Bytes(),
	}
	return &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{
		Version:   rsaSSAPKCS1SignerKeyVersion,
		PublicKey: pubKey,
		D:         rsaKey.D.Bytes(),
		P:         rsaKey.Primes[0].Bytes(),
		Q:         rsaKey.Primes[1].Bytes(),
		Dp:        rsaKey.Precomputed.Dp.Bytes(),
		Dq:        rsaKey.Precomputed.Dq.Bytes(),
		// In crypto/rsa `Qinv` is the "Chinese Remainder Theorem
		// coefficient q^(-1) mod p". This corresponds with `Crt` in
		// the Tink proto. This is unrelated to `CRTValues`, which
		// contains values specifically for additional primes, which
		// are not supported by Tink.
		Crt: rsaKey.Precomputed.Qinv.Bytes(),
	}, nil
}

func (km *rsaSSAPKCS1SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidRSASSAPKCS1SignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         rsaSSAPKCS1SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *rsaSSAPKCS1SignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := &rsassapkcs1pb.RsaSsaPkcs1PrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, err
	}
	if err := validateRSAPKCS1PrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         rsaSSAPKCS1VerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *rsaSSAPKCS1SignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == rsaSSAPKCS1SignerTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *rsaSSAPKCS1SignerKeyManager) TypeURL() string {
	return rsaSSAPKCS1SignerTypeURL
}
