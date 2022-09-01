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
	"crypto/rsa"
	"fmt"

	"errors"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	internal "github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/keyset"
	rsassapsspb "github.com/google/tink/go/proto/rsa_ssa_pss_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	rsaSSAPSSSignerKeyVersion = 0
	rsaSSAPSSSignerTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"
)

var (
	errInvalidRSASSAPSSSignKey = errors.New("rsassapss_signer_key_manager: invalid key")
)

type rsaSSAPSSSignerKeyManager struct{}

var _ registry.PrivateKeyManager = (*rsaSSAPSSSignerKeyManager)(nil)

func (km *rsaSSAPSSSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidRSASSAPSSSignKey
	}
	key := &rsassapsspb.RsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := validateRSAPSSPrivateKey(key); err != nil {
		return nil, err
	}
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: bytesToBigInt(key.GetPublicKey().GetN()),
			E: int(bytesToBigInt(key.GetPublicKey().GetE()).Uint64()),
		},
		D: bytesToBigInt(key.GetD()),
		Primes: []*big.Int{
			bytesToBigInt(key.GetP()),
			bytesToBigInt(key.GetQ()),
		},
		Precomputed: rsa.PrecomputedValues{
			Dp:   bytesToBigInt(key.GetDp()),
			Dq:   bytesToBigInt(key.GetDq()),
			Qinv: bytesToBigInt(key.GetCrt()),
		},
	}
	params := key.GetPublicKey().GetParams()
	if err := internal.Validate_RSA_SSA_PSS(hashName(params.GetSigHash()), int(params.GetSaltLength()), privKey); err != nil {
		return nil, err
	}
	return internal.New_RSA_SSA_PSS_Signer(hashName(params.GetSigHash()), int(params.GetSaltLength()), privKey)
}

func validateRSAPSSPrivateKey(privKey *rsassapsspb.RsaSsaPssPrivateKey) error {
	if err := keyset.ValidateKeyVersion(privKey.GetVersion(), rsaSSAPSSSignerKeyVersion); err != nil {
		return err
	}
	if err := validateRSAPSSPublicKey(privKey.GetPublicKey()); err != nil {
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
		return errInvalidRSASSAPSSSignKey
	}
	return nil
}

func (km *rsaSSAPSSSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	if serializedPrivKey == nil {
		return nil, errInvalidRSASSAPSSSignKey
	}
	privKey := &rsassapsspb.RsaSsaPssPrivateKey{}
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, err
	}
	if err := validateRSAPSSPrivateKey(privKey); err != nil {
		return nil, err
	}
	serializedPubKey, err := proto.Marshal(privKey.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         rsaSSAPSSVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *rsaSSAPSSSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	// TODO(b/173082704) implement in children CL.
	return nil, fmt.Errorf("not implemented")
}

func (km *rsaSSAPSSSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	// TODO(b/173082704) implement in children CL.
	return nil, fmt.Errorf("not implemented")
}

func (km *rsaSSAPSSSignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == rsaSSAPSSSignerTypeURL
}

func (km *rsaSSAPSSSignerKeyManager) TypeURL() string {
	return rsaSSAPSSSignerTypeURL
}
