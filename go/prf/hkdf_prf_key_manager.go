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

package prf

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
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

// Assert that hkdfprfKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*hkdfprfKeyManager)(nil)

// Primitive constructs a HKDF instance for the given serialized HKDFKey.
func (km *hkdfprfKeyManager) Primitive(serializedKey []byte) (any, error) {
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
	hash := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	hkdf, err := subtle.NewHKDFPRF(hash, key.GetKeyValue(), key.GetParams().GetSalt())
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
	keyValue := random.GetRandomBytes(keyFormat.GetKeySize())
	return &hkdfpb.HkdfPrfKey{
		Version:  hkdfprfKeyVersion,
		Params:   keyFormat.GetParams(),
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
		KeyMaterialType: km.KeyMaterialType(),
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

// KeyMaterialType returns the key material type of this KeyManager.
func (km *hkdfprfKeyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return tinkpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
func (km *hkdfprfKeyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
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
	if err := keyset.ValidateKeyVersion(keyFormat.GetVersion(), hkdfprfKeyVersion); err != nil {
		return nil, fmt.Errorf("hkdf_prf_key_manager: invalid key version: %s", err)
	}

	keyValue := make([]byte, keyFormat.GetKeySize())
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("hkdf_prf_key_manager: not enough pseudorandomness given")
	}

	return &hkdfpb.HkdfPrfKey{
		Version:  hkdfprfKeyVersion,
		Params:   keyFormat.GetParams(),
		KeyValue: keyValue,
	}, nil
}

// validateKey validates the given HKDFPRFKey. It only validates the version of the
// key because other parameters will be validated in primitive construction.
func (km *hkdfprfKeyManager) validateKey(key *hkdfpb.HkdfPrfKey) error {
	if err := keyset.ValidateKeyVersion(key.GetVersion(), hkdfprfKeyVersion); err != nil {
		return fmt.Errorf("hkdf_prf_key_manager: invalid version: %s", err)
	}
	keySize := uint32(len(key.GetKeyValue()))
	hash := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	return subtle.ValidateHKDFPRFParams(hash, keySize, key.GetParams().GetSalt())
}

// validateKeyFormat validates the given HKDFKeyFormat
func (km *hkdfprfKeyManager) validateKeyFormat(format *hkdfpb.HkdfPrfKeyFormat) error {
	hash := commonpb.HashType_name[int32(format.GetParams().GetHash())]
	return subtle.ValidateHKDFPRFParams(hash, format.GetKeySize(), format.GetParams().GetSalt())
}
