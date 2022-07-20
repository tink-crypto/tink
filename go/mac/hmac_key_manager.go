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

package mac

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	hmacKeyVersion = 0
	hmacTypeURL    = "type.googleapis.com/google.crypto.tink.HmacKey"
)

var errInvalidHMACKey = errors.New("hmac_key_manager: invalid key")
var errInvalidHMACKeyFormat = errors.New("hmac_key_manager: invalid key format")

// hmacKeyManager generates new HMAC keys and produces new instances of HMAC.
type hmacKeyManager struct{}

// Primitive constructs a HMAC instance for the given serialized HMACKey.
func (km *hmacKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidHMACKey
	}
	key := new(hmacpb.HmacKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidHMACKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash := commonpb.HashType_name[int32(key.Params.Hash)]
	hmac, err := subtle.NewHMAC(hash, key.KeyValue, key.Params.TagSize)
	if err != nil {
		return nil, err
	}
	return hmac, nil
}

// NewKey generates a new HMACKey according to specification in the given HMACKeyFormat.
func (km *hmacKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHMACKeyFormat
	}
	keyFormat := new(hmacpb.HmacKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHMACKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &hmacpb.HmacKey{
		Version:  hmacKeyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HMACKeyFormat. This should be used solely by the key management API.
func (km *hmacKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidHMACKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         hmacTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *hmacKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hmacTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *hmacKeyManager) TypeURL() string {
	return hmacTypeURL
}

// validateKey validates the given HMACKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *hmacKeyManager) validateKey(key *hmacpb.HmacKey) error {
	err := keyset.ValidateKeyVersion(key.Version, hmacKeyVersion)
	if err != nil {
		return fmt.Errorf("hmac_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	hash := commonpb.HashType_name[int32(key.Params.Hash)]
	return subtle.ValidateHMACParams(hash, keySize, key.Params.TagSize)
}

// validateKeyFormat validates the given HMACKeyFormat
func (km *hmacKeyManager) validateKeyFormat(format *hmacpb.HmacKeyFormat) error {
	if format.Params == nil {
		return fmt.Errorf("null HMAC params")
	}
	hash := commonpb.HashType_name[int32(format.Params.Hash)]
	return subtle.ValidateHMACParams(hash, format.KeySize, format.Params.TagSize)
}
