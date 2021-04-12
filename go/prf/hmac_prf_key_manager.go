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
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	hmacprfKeyVersion = 0
	hmacprfTypeURL    = "type.googleapis.com/google.crypto.tink.HmacPrfKey"
)

var errInvalidHMACPRFKey = errors.New("hmac_prf_key_manager: invalid key")
var errInvalidHMACPRFKeyFormat = errors.New("hmac_prf_key_manager: invalid key format")

// hmacprfKeyManager generates new HMAC PRF keys and produces new instances of HMAC.
type hmacprfKeyManager struct{}

// newHMACPRFKeyManager returns a new hmacprfKeyManager.
func newHMACPRFKeyManager() *hmacprfKeyManager {
	return new(hmacprfKeyManager)
}

// Primitive constructs a HMAC instance for the given serialized HMACKey.
func (km *hmacprfKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidHMACPRFKey
	}
	key := new(hmacpb.HmacPrfKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidHMACPRFKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash := commonpb.HashType_name[int32(key.Params.Hash)]
	hmac, err := subtle.NewHMACPRF(hash, key.KeyValue)
	if err != nil {
		return nil, err
	}
	return hmac, nil
}

// NewKey generates a new HMACPRFKey according to specification in the given HMACPRFKeyFormat.
func (km *hmacprfKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHMACPRFKeyFormat
	}
	keyFormat := new(hmacpb.HmacPrfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHMACPRFKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hmac_prf_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &hmacpb.HmacPrfKey{
		Version:  hmacprfKeyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HMACPRFKeyFormat. This should be used solely by the key management API.
func (km *hmacprfKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidHMACPRFKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         hmacprfTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *hmacprfKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hmacprfTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *hmacprfKeyManager) TypeURL() string {
	return hmacprfTypeURL
}

// validateKey validates the given HMACPRFKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *hmacprfKeyManager) validateKey(key *hmacpb.HmacPrfKey) error {
	err := keyset.ValidateKeyVersion(key.Version, hmacprfKeyVersion)
	if err != nil {
		return fmt.Errorf("hmac_prf_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	hash := commonpb.HashType_name[int32(key.Params.Hash)]
	return subtle.ValidateHMACPRFParams(hash, keySize)
}

// validateKeyFormat validates the given HMACKeyFormat
func (km *hmacprfKeyManager) validateKeyFormat(format *hmacpb.HmacPrfKeyFormat) error {
	if format.Params == nil {
		return fmt.Errorf("null HMAC params")
	}
	hash := commonpb.HashType_name[int32(format.Params.Hash)]
	return subtle.ValidateHMACPRFParams(hash, format.KeySize)
}
