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

package aead

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	// AesGcmKeyVersion is the maxmimal version of keys that this key manager supports.
	AesGcmKeyVersion = 0

	// AesGcmTypeURL is the url that this key manager supports.
	AesGcmTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmKey"
)

// common errors
var errInvalidAesGcmKey = fmt.Errorf("aes_gcm_key_manager: invalid key")
var errInvalidAesGcmKeyFormat = fmt.Errorf("aes_gcm_key_manager: invalid key format")

// AesGcmKeyManager is an implementation of KeyManager interface.
// It generates new AesGcmKey keys and produces new instances of AesGcm subtle.
type AesGcmKeyManager struct{}

// Assert that aesGcmKeyManager implements the KeyManager interface.
var _ tink.KeyManager = (*AesGcmKeyManager)(nil)

// NewAesGcmKeyManager creates a new aesGcmKeyManager.
func NewAesGcmKeyManager() *AesGcmKeyManager {
	return new(AesGcmKeyManager)
}

// GetPrimitiveFromSerializedKey creates an AesGcm subtle for the given
// serialized AesGcmKey proto.
func (km *AesGcmKeyManager) GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidAesGcmKey
	}
	key := new(gcmpb.AesGcmKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidAesGcmKey
	}
	return km.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKey creates an AesGcm subtle for the given AesGcmKey proto.
func (km *AesGcmKeyManager) GetPrimitiveFromKey(m proto.Message) (interface{}, error) {
	key, ok := m.(*gcmpb.AesGcmKey)
	if !ok {
		return nil, errInvalidAesGcmKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := aead.NewAesGcm(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// NewKeyFromSerializedKeyFormat creates a new key according to specification
// the given serialized AesGcmKeyFormat.
func (km *AesGcmKeyManager) NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAesGcmKeyFormat
	}
	keyFormat := new(gcmpb.AesGcmKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAesGcmKeyFormat
	}
	return km.NewKeyFromKeyFormat(keyFormat)
}

// NewKeyFromKeyFormat creates a new key according to specification in the
// given AesGcmKeyFormat.
func (km *AesGcmKeyManager) NewKeyFromKeyFormat(m proto.Message) (proto.Message, error) {
	keyFormat, ok := m.(*gcmpb.AesGcmKeyFormat)
	if !ok {
		return nil, errInvalidAesGcmKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &gcmpb.AesGcmKey{
		Version:  AesGcmKeyVersion,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized AesGcmKeyFormat. It should be used solely by the key management API.
func (km *AesGcmKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKeyFromSerializedKeyFormat(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         AesGcmTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *AesGcmKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == AesGcmTypeURL
}

// GetKeyType returns the key type of keys managed by this key manager.
func (km *AesGcmKeyManager) GetKeyType() string {
	return AesGcmTypeURL
}

// validateKey validates the given AesGcmKey.
func (km *AesGcmKeyManager) validateKey(key *gcmpb.AesGcmKey) error {
	err := tink.ValidateVersion(key.Version, AesGcmKeyVersion)
	if err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	if err := aead.ValidateAesKeySize(keySize); err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given AesGcmKeyFormat.
func (km *AesGcmKeyManager) validateKeyFormat(format *gcmpb.AesGcmKeyFormat) error {
	if err := aead.ValidateAesKeySize(format.KeySize); err != nil {
		return fmt.Errorf("aes_gcm_key_manager: %s", err)
	}
	return nil
}
