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

	"github.com/golang/protobuf/proto"
	subtleSignature "github.com/google/tink/go/subtle/signature"
	"github.com/google/tink/go/tink"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	// EcdsaVerifyKeyVersion is the maximum version of keys that this manager supports.
	EcdsaVerifyKeyVersion = 0

	// EcdsaVerifyTypeURL is the only type URL that this manager supports.
	EcdsaVerifyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
)

// common errors
var errInvalidEcdsaVerifyKey = fmt.Errorf("ecdsa_verify_key_manager: invalid key")
var errEcdsaVerifyNotImplemented = fmt.Errorf("ecdsa_verify_key_manager: not implemented")

// EcdsaVerifyKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type EcdsaVerifyKeyManager struct{}

// Assert that EcdsaVerifyKeyManager implements the KeyManager interface.
var _ tink.KeyManager = (*EcdsaVerifyKeyManager)(nil)

// NewEcdsaVerifyKeyManager creates a new EcdsaVerifyKeyManager.
func NewEcdsaVerifyKeyManager() *EcdsaVerifyKeyManager {
	return new(EcdsaVerifyKeyManager)
}

// GetPrimitiveFromSerializedKey creates an EcdsaVerify subtle for the given
// serialized EcdsaPublicKey proto.
func (km *EcdsaVerifyKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidEcdsaVerifyKey
	}
	key := new(ecdsapb.EcdsaPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidEcdsaVerifyKey
	}
	return km.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKey creates an EcdsaVerify subtle for the given EcdsaPublicKey proto.
func (km *EcdsaVerifyKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
	key, ok := m.(*ecdsapb.EcdsaPublicKey)
	if !ok {
		return nil, errInvalidEcdsaVerifyKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("ecdsa_verify_key_manager: %s", err)
	}
	hash, curve, encoding := GetEcdsaParamNames(key.Params)
	ret, err := subtleSignature.NewEcdsaVerify(hash, curve, encoding, key.X, key.Y)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_verify_key_manager: invalid key: %s", err)
	}
	return ret, nil
}

// NewKeyFromSerializedKeyFormat is not implemented
func (km *EcdsaVerifyKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errEcdsaVerifyNotImplemented
}

// NewKeyFromKeyFormat is not implemented
func (km *EcdsaVerifyKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
	return nil, errEcdsaVerifyNotImplemented
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized EcdsaKeyFormat. It should be used solely by the key management API.
func (km *EcdsaVerifyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errEcdsaVerifyNotImplemented
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *EcdsaVerifyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == EcdsaVerifyTypeURL
}

// GetKeyType returns the key type of keys managed by this key manager.
func (km *EcdsaVerifyKeyManager) GetKeyType() string {
	return EcdsaVerifyTypeURL
}

// validateKey validates the given EcdsaPublicKey.
func (km *EcdsaVerifyKeyManager) validateKey(key *ecdsapb.EcdsaPublicKey) error {
	if err := tink.ValidateVersion(key.Version, EcdsaVerifyKeyVersion); err != nil {
		return fmt.Errorf("ecdsa_verify_key_manager: %s", err)
	}
	hash, curve, encoding := GetEcdsaParamNames(key.Params)
	return subtleSignature.ValidateEcdsaParams(hash, curve, encoding)
}
