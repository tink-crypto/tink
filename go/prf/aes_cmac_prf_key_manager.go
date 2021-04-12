// Copyright 2020 Google LLC
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

package prf

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/prf/subtle"
	"github.com/google/tink/go/subtle/random"
	cmacpb "github.com/google/tink/go/proto/aes_cmac_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	aescmacprfKeyVersion = 0
	aescmacprfTypeURL    = "type.googleapis.com/google.crypto.tink.AesCmacPrfKey"
)

var errInvalidAESCMACPRFKey = errors.New("aes_cmac_prf_key_manager: invalid key")
var errInvalidAESCMACPRFKeyFormat = errors.New("aes_cmac_prf_key_manager: invalid key format")

// aescmacprfKeyManager generates new AES-CMAC keys and produces new instances of AES-CMAC.
type aescmacprfKeyManager struct{}

// newAESCMACPRFKeyManager returns a new aescmacprfKeyManager.
func newAESCMACPRFKeyManager() *aescmacprfKeyManager {
	return new(aescmacprfKeyManager)
}

// Primitive constructs a AES-CMAC instance for the given serialized AESCMACPRFKey.
func (km *aescmacprfKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidAESCMACPRFKey
	}
	key := new(cmacpb.AesCmacPrfKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidAESCMACPRFKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	return subtle.NewAESCMACPRF(key.KeyValue)
}

// NewKey generates a new AESCMACPRFKey according to specification in the given AESCMACPRFKeyFormat.
func (km *aescmacprfKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAESCMACPRFKeyFormat
	}
	keyFormat := new(cmacpb.AesCmacPrfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAESCMACPRFKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_cmac_prf_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &cmacpb.AesCmacPrfKey{
		Version:  aescmacprfKeyVersion,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized AESCMACPRFKeyFormat. This should be used solely by the key management API.
func (km *aescmacprfKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidAESCMACPRFKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         aescmacprfTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *aescmacprfKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aescmacprfTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *aescmacprfKeyManager) TypeURL() string {
	return aescmacprfTypeURL
}

// validateKey validates the given AESCMACPRFKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *aescmacprfKeyManager) validateKey(key *cmacpb.AesCmacPrfKey) error {
	err := keyset.ValidateKeyVersion(key.Version, aescmacprfKeyVersion)
	if err != nil {
		return fmt.Errorf("aes_cmac_prf_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	return subtle.ValidateAESCMACPRFParams(keySize)
}

// validateKeyFormat validates the given HMACKeyFormat
func (km *aescmacprfKeyManager) validateKeyFormat(format *cmacpb.AesCmacPrfKeyFormat) error {
	return subtle.ValidateAESCMACPRFParams(format.KeySize)
}
