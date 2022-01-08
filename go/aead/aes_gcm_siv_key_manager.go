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

package aead

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	gcmsivpb "github.com/google/tink/go/proto/aes_gcm_siv_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	aesGCMSIVKeyVersion = 0
	aesGCMSIVTypeURL    = "type.googleapis.com/google.crypto.tink.AesGcmSivKey"
)

// common errors
var errInvalidAESGCMSIVKey = fmt.Errorf("aes_gcm_siv_key_manager: invalid key")
var errInvalidAESGCMSIVKeyFormat = fmt.Errorf("aes_gcm_siv_key_manager: invalid key format")

// aesGCMSIVKeyManager is an implementation of KeyManager interface.
// It generates new AESGCMSIVKey keys and produces new instances of AESGCMSIV subtle.
type aesGCMSIVKeyManager struct{}

// Assert that aesGCMSIVKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*aesGCMSIVKeyManager)(nil)

// Primitive creates an AESGCMSIV subtle for the given serialized AESGCMSIVKey proto.
func (km *aesGCMSIVKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidAESGCMSIVKey
	}
	key := new(gcmsivpb.AesGcmSivKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidAESGCMSIVKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := subtle.NewAESGCMSIV(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// NewKey creates a new key according to specification the given serialized AESGCMSIVKeyFormat.
func (km *aesGCMSIVKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAESGCMSIVKeyFormat
	}
	keyFormat := new(gcmsivpb.AesGcmSivKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAESGCMSIVKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_siv_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &gcmsivpb.AesGcmSivKey{
		Version:  aesGCMSIVKeyVersion,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// AESGCMSIVKeyFormat.
// It should be used solely by the key management API.
func (km *aesGCMSIVKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         aesGCMSIVTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *aesGCMSIVKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aesGCMSIVTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *aesGCMSIVKeyManager) TypeURL() string {
	return aesGCMSIVTypeURL
}

// validateKey validates the given AESGCMSIVKey.
func (km *aesGCMSIVKeyManager) validateKey(key *gcmsivpb.AesGcmSivKey) error {
	err := keyset.ValidateKeyVersion(key.Version, aesGCMSIVKeyVersion)
	if err != nil {
		return fmt.Errorf("aes_gcm_siv_key_manager: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	if err := subtle.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_gcm_siv_key_manager: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given AESGCMSIVKeyFormat.
func (km *aesGCMSIVKeyManager) validateKeyFormat(format *gcmsivpb.AesGcmSivKeyFormat) error {
	if err := subtle.ValidateAESKeySize(format.KeySize); err != nil {
		return fmt.Errorf("aes_gcm_siv_key_manager: %s", err)
	}
	return nil
}
