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

package streamingaead

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	subtleaead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead/subtle"
	"github.com/google/tink/go/subtle/random"
	ghpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	aesGCMHKDFKeyVersion = 0
	aesGCMHKDFTypeURL    = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"
)

var (
	errInvalidAESGCMHKDFKey       = errors.New("aes_gcm_hkdf_key_manager: invalid key")
	errInvalidAESGCMHKDFKeyFormat = errors.New("aes_gcm_hkdf_key_manager: invalid key format")
)

// aesGCMHKDFKeyManager is an implementation of KeyManager interface.
// It generates new AESGCMHKDFKey keys and produces new instances of AESGCMHKDF subtle.
type aesGCMHKDFKeyManager struct{}

// Primitive creates an AESGCMHKDF subtle for the given serialized AESGCMHKDFKey proto.
func (km *aesGCMHKDFKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidAESGCMHKDFKey
	}
	key := &ghpb.AesGcmHkdfStreamingKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidAESGCMHKDFKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := subtle.NewAESGCMHKDF(
		key.KeyValue,
		key.Params.HkdfHashType.String(),
		int(key.Params.DerivedKeySize),
		int(key.Params.CiphertextSegmentSize),
		// no first segment offset
		0)
	if err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: cannot create new primitive: %s", err)
	}
	return ret, nil
}

// NewKey creates a new key according to specification in the given serialized
// AesGcmHkdfStreamingKeyFormat.
func (km *aesGCMHKDFKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAESGCMHKDFKeyFormat
	}
	keyFormat := &ghpb.AesGcmHkdfStreamingKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAESGCMHKDFKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_gcm_hkdf_key_manager: invalid key format: %s", err)
	}
	return &ghpb.AesGcmHkdfStreamingKey{
		Version:  aesGCMHKDFKeyVersion,
		KeyValue: random.GetRandomBytes(keyFormat.KeySize),
		Params:   keyFormat.Params,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized AesGcmHkdfStreamingKeyFormat.
// It should be used solely by the key management API.
func (km *aesGCMHKDFKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         km.TypeURL(),
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *aesGCMHKDFKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aesGCMHKDFTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *aesGCMHKDFKeyManager) TypeURL() string {
	return aesGCMHKDFTypeURL
}

// validateKey validates the given AESGCMHKDFKey.
func (km *aesGCMHKDFKeyManager) validateKey(key *ghpb.AesGcmHkdfStreamingKey) error {
	err := keyset.ValidateKeyVersion(key.Version, aesGCMHKDFKeyVersion)
	if err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	keySize := uint32(len(key.KeyValue))
	if err := subtleaead.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	if err := km.validateParams(key.Params); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given AESGCMHKDFKeyFormat.
func (km *aesGCMHKDFKeyManager) validateKeyFormat(format *ghpb.AesGcmHkdfStreamingKeyFormat) error {
	if err := subtleaead.ValidateAESKeySize(format.KeySize); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	if err := km.validateParams(format.Params); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	return nil
}

// validateKeyFormat validates the given AESGCMHKDFKeyFormat.
func (km *aesGCMHKDFKeyManager) validateParams(params *ghpb.AesGcmHkdfStreamingParams) error {
	if err := subtleaead.ValidateAESKeySize(params.DerivedKeySize); err != nil {
		return fmt.Errorf("aes_gcm_hkdf_key_manager: %s", err)
	}
	if params.HkdfHashType == commonpb.HashType_UNKNOWN_HASH {
		return errors.New("unknown HKDF hash type")
	}
	minSegmentSize := params.DerivedKeySize + subtle.AESGCMHKDFNoncePrefixSizeInBytes + subtle.AESGCMHKDFTagSizeInBytes + 2
	if params.CiphertextSegmentSize < minSegmentSize {
		return fmt.Errorf("ciphertext segment_size must be at least (derivedKeySize + noncePrefixInBytes + tagSizeInBytes + 2)")
	}
	return nil
}
