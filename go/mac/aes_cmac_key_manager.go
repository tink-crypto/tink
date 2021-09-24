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

package mac

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
	cmacpb "github.com/google/tink/go/proto/aes_cmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	cmacKeyVersion = 0
	cmacTypeURL    = "type.googleapis.com/google.crypto.tink.AesCmacKey"
)

var errInvalidCMACKey = errors.New("aes_cmac_key_manager: invalid key")
var errInvalidCMACKeyFormat = errors.New("aes_cmac_key_manager: invalid key format")

// cmacKeyManager generates new AES-CMAC keys and produces new instances of AES-CMAC.
type aescmacKeyManager struct{}

// Primitive constructs a AES-CMAC instance for the given serialized CMACKey.
func (km *aescmacKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidCMACKey
	}
	key := new(cmacpb.AesCmacKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidCMACKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	cmac, err := subtle.NewAESCMAC(key.KeyValue, key.Params.TagSize)
	if err != nil {
		return nil, err
	}
	return cmac, nil
}

// NewKey generates a new AesCmacKey according to specification in the given AesCmacKeyFormat.
func (km *aescmacKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidCMACKeyFormat
	}
	keyFormat := new(cmacpb.AesCmacKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidCMACKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_cmac_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &cmacpb.AesCmacKey{
		Version:  cmacKeyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized AesCmacKeyFormat. This should be used solely by the key management API.
func (km *aescmacKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidCMACKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         cmacTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *aescmacKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == cmacTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *aescmacKeyManager) TypeURL() string {
	return cmacTypeURL
}

// validateKey validates the given AesCmacKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *aescmacKeyManager) validateKey(key *cmacpb.AesCmacKey) error {
	err := keyset.ValidateKeyVersion(key.Version, cmacKeyVersion)
	if err != nil {
		return fmt.Errorf("aes_cmac_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	return subtle.ValidateCMACParams(keySize, key.Params.TagSize)
}

// validateKeyFormat validates the given AesCmacKeyFormat
func (km *aescmacKeyManager) validateKeyFormat(format *cmacpb.AesCmacKeyFormat) error {
	if format.Params == nil {
		return fmt.Errorf("null AES-CMAC params")
	}
	return subtle.ValidateCMACParams(format.KeySize, format.Params.TagSize)
}
