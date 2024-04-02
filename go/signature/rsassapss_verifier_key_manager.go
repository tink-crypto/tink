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

package signature

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	internal "github.com/google/tink/go/internal/signature"
	"github.com/google/tink/go/keyset"
	rsassapsspb "github.com/google/tink/go/proto/rsa_ssa_pss_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	rsaSSAPSSVerifierKeyVersion = 0
	rsaSSAPSSVerifierTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey"
)

var (
	errInvalidRSASSAPSSVerifierKey = errors.New("rsassapss_verifier_key_manager: invalid key")
	errRSASSAPSSNotImplemented     = errors.New("rsassapss_verifier_key_manager: not implemented")
)

type rsaSSAPSSVerifierKeyManager struct{}

var _ (registry.KeyManager) = (*rsaSSAPSSVerifierKeyManager)(nil)

func (km *rsaSSAPSSVerifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidRSASSAPSSVerifierKey
	}
	key := &rsassapsspb.RsaSsaPssPublicKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidRSASSAPSSVerifierKey
	}
	if err := validateRSAPSSPublicKey(key); err != nil {
		return nil, err
	}
	pubKey := &rsa.PublicKey{
		E: int(new(big.Int).SetBytes(key.E).Uint64()),
		N: new(big.Int).SetBytes(key.N),
	}
	return internal.New_RSA_SSA_PSS_Verifier(hashName(key.GetParams().GetSigHash()), int(key.GetParams().GetSaltLength()), pubKey)
}

func validateRSAPSSPublicKey(pubKey *rsassapsspb.RsaSsaPssPublicKey) error {
	if err := keyset.ValidateKeyVersion(pubKey.GetVersion(), rsaSSAPSSVerifierKeyVersion); err != nil {
		return err
	}
	if pubKey.GetParams().GetSigHash() != pubKey.GetParams().GetMgf1Hash() {
		return fmt.Errorf("signature hash and MGF1 hash function must match")
	}
	if pubKey.GetParams().GetSaltLength() < 0 {
		return fmt.Errorf("salt length can't be negative")
	}
	return validateRSAPubKeyParams(
		pubKey.GetParams().GetSigHash(),
		new(big.Int).SetBytes(pubKey.GetN()).BitLen(),
		pubKey.GetE())
}

func (km *rsaSSAPSSVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errRSASSAPSSNotImplemented
}

func (km *rsaSSAPSSVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errRSASSAPSSNotImplemented
}

func (km *rsaSSAPSSVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == rsaSSAPSSVerifierTypeURL
}

func (km *rsaSSAPSSVerifierKeyManager) TypeURL() string {
	return rsaSSAPSSVerifierTypeURL
}
