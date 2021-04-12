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
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	hkdfprfKeyVersion = 0
	hkdfprfTypeURL    = "type.googleapis.com/google.crypto.tink.HkdfPrfKey"
)

var errInvalidHKDFPRFKey = errors.New("hkdf_prf_key_manager: invalid key")
var errInvalidHKDFPRFKeyFormat = errors.New("hkdf_prf_key_manager: invalid key format")

// hkdfprfKeyManager generates new HKDF PRF keys and produces new instances of HKDF.
type hkdfprfKeyManager struct{}

// newHKDFPRFKeyManager returns a new hkdfprfKeyManager.
func newHKDFPRFKeyManager() *hkdfprfKeyManager {
	return new(hkdfprfKeyManager)
}

// Primitive constructs a HKDF instance for the given serialized HKDFKey.
func (km *hkdfprfKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidHKDFPRFKey
	}
	key := new(hkdfpb.HkdfPrfKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidHKDFPRFKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hash := commonpb.HashType_name[int32(key.Params.Hash)]
	hkdf, err := subtle.NewHKDFPRF(hash, key.KeyValue, key.Params.Salt)
	if err != nil {
		return nil, err
	}
	return hkdf, nil
}

// NewKey generates a new HKDFPRFKey according to specification in the given HKDFPRFKeyFormat.
func (km *hkdfprfKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHKDFPRFKeyFormat
	}
	keyFormat := new(hkdfpb.HkdfPrfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHKDFPRFKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("hkdf_prf_key_manager: invalid key format: %s", err)
	}
	keyValue := random.GetRandomBytes(keyFormat.KeySize)
	return &hkdfpb.HkdfPrfKey{
		Version:  hkdfprfKeyVersion,
		Params:   keyFormat.Params,
		KeyValue: keyValue,
	}, nil
}

// NewKeyData generates a new KeyData according to specification in the given
// serialized HKDFPRFKeyFormat. This should be used solely by the key management API.
func (km *hkdfprfKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidHKDFPRFKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         hkdfprfTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport checks whether this KeyManager supports the given key type.
func (km *hkdfprfKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hkdfprfTypeURL
}

// TypeURL returns the type URL of keys managed by this KeyManager.
func (km *hkdfprfKeyManager) TypeURL() string {
	return hkdfprfTypeURL
}

// validateKey validates the given HKDFPRFKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *hkdfprfKeyManager) validateKey(key *hkdfpb.HkdfPrfKey) error {
	err := keyset.ValidateKeyVersion(key.Version, hkdfprfKeyVersion)
	if err != nil {
		return fmt.Errorf("hkdf_prf_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	hash := commonpb.HashType_name[int32(key.Params.Hash)]
	return subtle.ValidateHKDFPRFParams(hash, keySize, key.Params.Salt)
}

// validateKeyFormat validates the given HKDFKeyFormat
func (km *hkdfprfKeyManager) validateKeyFormat(format *hkdfpb.HkdfPrfKeyFormat) error {
	if format.Params == nil {
		return fmt.Errorf("null HKDF params")
	}
	hash := commonpb.HashType_name[int32(format.Params.Hash)]
	return subtle.ValidateHKDFPRFParams(hash, format.KeySize, format.Params.Salt)
}
