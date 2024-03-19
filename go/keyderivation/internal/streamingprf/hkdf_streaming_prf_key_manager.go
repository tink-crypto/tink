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
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// TODO(b/260619626): HKDF PRF and HKDF Streaming PRF currently share the same
// type URL. This is fine as HKDFStreamingPRFKeyManager is not in the global
// registry. HKDF PRF and HKDF Streaming PRF will eventually share the same key
// manager, rendering this one obsolete.

const (
	hkdfStreamingPRFKeyVersion = 0
	hkdfPRFTypeURL             = "type.googleapis.com/google.crypto.tink.HkdfPrfKey"
)

var (
	errInvalidHKDFStreamingPRFKey       = errors.New("hkdf_streaming_prf_key_manager: invalid key")
	errInvalidHKDFStreamingPRFKeyFormat = errors.New("hkdf_streaming_prf_key_manager: invalid key format")
	errHKDFStreamingPRFNotImplemented   = errors.New("hkdf_streaming_prf_key_manager: not implemented")
)

// HKDFStreamingPRFKeyManager is a KeyManager for HKDF Streaming PRF keys. It is
// exported for use in keyderivation.prfBasedDeriver. This is not part of the
// public API as this is in internal/.
type HKDFStreamingPRFKeyManager struct{}

var _ registry.KeyManager = (*HKDFStreamingPRFKeyManager)(nil)

// Primitive constructs a primitive instance for the key given in serializedKey.
func (km *HKDFStreamingPRFKeyManager) Primitive(serializedKey []byte) (any, error) {
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
	hashName := commonpb.HashType_name[int32(key.GetParams().GetHash())]
	return newHKDFStreamingPRF(hashName, key.GetKeyValue(), key.GetParams().GetSalt())
}

// NewKey generates a new key according to specification in serializedKeyFormat.
// It is not implemented for this KeyManager to prevent the generation of keys
// of this key type.
func (km *HKDFStreamingPRFKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errHKDFStreamingPRFNotImplemented
}

// NewKeyData generates a new KeyData according to specification in
// serializedkeyFormat. This should be used solely by the key management API.
// It is not implemented for this KeyManager to prevent the generation of keys
// of this key type.
func (km *HKDFStreamingPRFKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errHKDFStreamingPRFNotImplemented
}

// DoesSupport returns true iff this KeyManager supports key type identified by
// typeURL.
func (km *HKDFStreamingPRFKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == hkdfPRFTypeURL
}

// TypeURL returns the type URL that identifes the key type of keys managed by
// this KeyManager.
func (km *HKDFStreamingPRFKeyManager) TypeURL() string {
	return hkdfPRFTypeURL
}
