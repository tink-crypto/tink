// Copyright 2018 Google LLC
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
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature/subtle"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	ecdsaVerifierKeyVersion = 0
	ecdsaVerifierTypeURL    = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
)

// common errors
var errInvalidECDSAVerifierKey = fmt.Errorf("ecdsa_verifier_key_manager: invalid key")
var errECDSAVerifierNotImplemented = fmt.Errorf("ecdsa_verifier_key_manager: not implemented")

// ecdsaVerifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type ecdsaVerifierKeyManager struct{}

// Primitive creates an ECDSAVerifier subtle for the given serialized ECDSAPublicKey proto.
func (km *ecdsaVerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDSAVerifierKey
	}
	key := new(ecdsapb.EcdsaPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidECDSAVerifierKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("ecdsa_verifier_key_manager: %s", err)
	}
	hash, curve, encoding := getECDSAParamNames(key.Params)
	ret, err := subtle.NewECDSAVerifier(hash, curve, encoding, key.X, key.Y)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_verifier_key_manager: invalid key: %s", err)
	}
	return ret, nil
}

// NewKey is not implemented.
func (km *ecdsaVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errECDSAVerifierNotImplemented
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ECDSAKeyFormat. It should be used solely by the key management API.
func (km *ecdsaVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errECDSAVerifierNotImplemented
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdsaVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdsaVerifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdsaVerifierKeyManager) TypeURL() string {
	return ecdsaVerifierTypeURL
}

// validateKey validates the given ECDSAPublicKey.
func (km *ecdsaVerifierKeyManager) validateKey(key *ecdsapb.EcdsaPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, ecdsaVerifierKeyVersion); err != nil {
		return fmt.Errorf("ecdsa_verifier_key_manager: %s", err)
	}
	hash, curve, encoding := getECDSAParamNames(key.Params)
	return subtle.ValidateECDSAParams(hash, curve, encoding)
}
