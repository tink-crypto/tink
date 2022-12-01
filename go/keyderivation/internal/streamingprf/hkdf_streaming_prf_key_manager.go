// Copyright 2022 Google LLC
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

package streamingprf

import (
	"errors"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	hkdfStreamingPRFKeyVersion = 0
	hkdfStreamingPRFTypeURL    = "type.googleapis.com/google.crypto.tink.HkdfStreamingPrfKey"
)

var (
	errInvalidHKDFStreamingPRFKey       = errors.New("hkdf_streaming_prf_key_manager: invalid key")
	errInvalidHKDFStreamingPRFKeyFormat = errors.New("hkdf_streaming_prf_key_manager: invalid key format")
)

// HKDFStreamingPRFKeyManager is a KeyManager for HKDF Streaming PRF keys. It is
// exported for use in keyderivation.prfBasedDeriver. This is not part of the
// public API as this is in internal/.
type HKDFStreamingPRFKeyManager struct{}

var _ registry.KeyManager = (*HKDFStreamingPRFKeyManager)(nil)

// Primitive constructs a primitive instance for the key given in serializedKey.
func (km *HKDFStreamingPRFKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidHKDFStreamingPRFKey
	}
	key := &hkdfpb.HkdfPrfKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidHKDFStreamingPRFKey
	}
	if keyset.ValidateKeyVersion(key.GetVersion(), hkdfStreamingPRFKeyVersion) != nil {
		return nil, errInvalidHKDFStreamingPRFKey
	}
	return newHKDFStreamingPRF(hashNameFromHKDFPRFParams(key.GetParams()), key.GetKeyValue(), key.GetParams().GetSalt())
}

// NewKey generates a new key according to specification in serializedKeyFormat.
func (km *HKDFStreamingPRFKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidHKDFStreamingPRFKeyFormat
	}
	keyFormat := &hkdfpb.HkdfPrfKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidHKDFStreamingPRFKeyFormat
	}
	if err := validateHKDFStreamingPRFParams(hashNameFromHKDFPRFParams(keyFormat.GetParams()), int(keyFormat.GetKeySize())); err != nil {
		return nil, err
	}
	return &hkdfpb.HkdfPrfKey{
		Version:  hkdfStreamingPRFKeyVersion,
		Params:   keyFormat.GetParams(),
		KeyValue: random.GetRandomBytes(keyFormat.GetKeySize()),
	}, nil
}

// NewKeyData generates a new KeyData according to specification in
// serializedkeyFormat. This should be used solely by the key management API.
func (km *HKDFStreamingPRFKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidHKDFStreamingPRFKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         hkdfStreamingPRFTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport returns true iff this KeyManager supports key type identified by
// typeURL.
func (km *HKDFStreamingPRFKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hkdfStreamingPRFTypeURL
}

// TypeURL returns the type URL that identifes the key type of keys managed by
// this KeyManager.
func (km *HKDFStreamingPRFKeyManager) TypeURL() string {
	return hkdfStreamingPRFTypeURL
}

func hashNameFromHKDFPRFParams(params *hkdfpb.HkdfPrfParams) string {
	return commonpb.HashType_name[int32(params.GetHash())]
}
