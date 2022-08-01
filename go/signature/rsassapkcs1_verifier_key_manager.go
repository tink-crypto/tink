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
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature/internal"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	rsassapkcs1pb "github.com/google/tink/go/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	rsaSSAPKCS1VerifierKeyVersion = 0
	rsaSSAPKCS1VerifierTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
)

var (
	errRSASSAPKCS1NotImplemented = errors.New("rsassapkcs1_verifier_key_manager: not implemented")
)

type rsaSSAPKCS1VerifierKeyManager struct{}

// NewRSASSAPKCS1VerifierKeyManager returns a new verifier key manager instance:
// TODO(b/173082704): Delete in CL/463428483, only used for temporary testing to avoid test breakage.
func NewRSASSAPKCS1VerifierKeyManager() registry.KeyManager {
	return &rsaSSAPKCS1VerifierKeyManager{}
}

var _ registry.KeyManager = (*rsaSSAPKCS1VerifierKeyManager)(nil)

func (km *rsaSSAPKCS1VerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("rsassapkcs1_verifier_key_manager: invalid serialized public key")
	}
	key := &rsassapkcs1pb.RsaSsaPkcs1PublicKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := keyset.ValidateKeyVersion(key.Version, rsaSSAPKCS1VerifierKeyVersion); err != nil {
		return nil, err
	}

	e := new(big.Int).SetBytes(key.E)
	if !e.IsInt64() {
		return nil, fmt.Errorf("rsassapkcs1_verifier_key_manager: public exponent can't fit in 64 bit number")
	}
	keyData := &rsa.PublicKey{
		E: int(e.Int64()),
		N: new(big.Int).SetBytes(key.N),
	}
	return internal.New_RSA_SSA_PKCS1_Verifier(commonpb.HashType_name[int32(key.Params.HashType)], keyData)
}

func (km *rsaSSAPKCS1VerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errRSASSAPKCS1NotImplemented
}

func (km *rsaSSAPKCS1VerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errRSASSAPKCS1NotImplemented
}

func (km *rsaSSAPKCS1VerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == rsaSSAPKCS1VerifierTypeURL
}

func (km *rsaSSAPKCS1VerifierKeyManager) TypeURL() string {
	return rsaSSAPKCS1VerifierTypeURL
}
