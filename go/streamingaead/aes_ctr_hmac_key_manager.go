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

	"google.golang.org/protobuf/proto"
	subtleaead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/keyset"
	subtlemac "github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/streamingaead/subtle"
	"github.com/google/tink/go/subtle/random"
	chpb "github.com/google/tink/go/proto/aes_ctr_hmac_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	aesCTRHMACKeyVersion = 0
	aesCTRHMACTypeURL    = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"
)

var (
	errInvalidAESCTRHMACKey       = errors.New("aes_ctr_hmac_key_manager: invalid key")
	errInvalidAESCTRHMACKeyFormat = errors.New("aes_ctr_hmac_key_manager: invalid key format")
)

// aesCTRHMACKeyManager is an implementation of KeyManager interface.
//
// It generates new AESCTRHMACKey keys and produces new instances of AESCTRHMAC
// subtle.
type aesCTRHMACKeyManager struct{}

// Primitive creates an AESCTRHMAC subtle for the given serialized
// AESCTRHMACKey proto.
func (km *aesCTRHMACKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidAESCTRHMACKey
	}
	key := &chpb.AesCtrHmacStreamingKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidAESCTRHMACKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	p, err := subtle.NewAESCTRHMAC(
		key.KeyValue,
		key.Params.HkdfHashType.String(),
		int(key.Params.DerivedKeySize),
		key.Params.HmacParams.Hash.String(),
		int(key.Params.HmacParams.TagSize),
		int(key.Params.CiphertextSegmentSize),
		// No first segment offset.
		0)
	if err != nil {
		return nil, fmt.Errorf("aes_ctr_hmac_key_manager: cannot create new primitive: %s", err)
	}
	return p, nil
}

// NewKey creates a new key according to specification in the given serialized
// AesCtrHmacStreamingKeyFormat.
func (km *aesCTRHMACKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAESCTRHMACKeyFormat
	}
	keyFormat := &chpb.AesCtrHmacStreamingKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAESCTRHMACKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("%s: %s", errInvalidAESCTRHMACKeyFormat, err)
	}
	return &chpb.AesCtrHmacStreamingKey{
		Version:  aesCTRHMACKeyVersion,
		KeyValue: random.GetRandomBytes(keyFormat.KeySize),
		Params:   keyFormat.Params,
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given
// serialized AesCtrHmacStreamingKeyFormat.
//
// It should be used solely by the key management API.
func (km *aesCTRHMACKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
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
func (km *aesCTRHMACKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aesCTRHMACTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *aesCTRHMACKeyManager) TypeURL() string {
	return aesCTRHMACTypeURL
}

// validateKey validates the given AESCTRHMACKey.
func (km *aesCTRHMACKeyManager) validateKey(key *chpb.AesCtrHmacStreamingKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, aesCTRHMACKeyVersion); err != nil {
		return err
	}
	keySize := uint32(len(key.KeyValue))
	if err := subtleaead.ValidateAESKeySize(keySize); err != nil {
		return err
	}
	if err := km.validateParams(key.Params); err != nil {
		return err
	}
	return nil
}

// validateKeyFormat validates the given AESCTRHMACKeyFormat.
func (km *aesCTRHMACKeyManager) validateKeyFormat(format *chpb.AesCtrHmacStreamingKeyFormat) error {
	if err := subtleaead.ValidateAESKeySize(format.KeySize); err != nil {
		return err
	}
	if err := km.validateParams(format.Params); err != nil {
		return err
	}
	return nil
}

// validateParams validates the given AESCTRHMACStreamingParams.
func (km *aesCTRHMACKeyManager) validateParams(params *chpb.AesCtrHmacStreamingParams) error {
	if err := subtleaead.ValidateAESKeySize(params.DerivedKeySize); err != nil {
		return err
	}
	if params.HkdfHashType == commonpb.HashType_UNKNOWN_HASH {
		return errors.New("unknown HKDF hash type")
	}
	if params.HmacParams.Hash == commonpb.HashType_UNKNOWN_HASH {
		return errors.New("uknown tag algorithm")
	}
	hmacHash := commonpb.HashType_name[int32(params.HmacParams.Hash)]
	if err := subtlemac.ValidateHMACParams(hmacHash, subtle.AESCTRHMACKeySizeInBytes, params.HmacParams.TagSize); err != nil {
		return err
	}
	minSegmentSize := params.DerivedKeySize + subtle.AESCTRHMACNoncePrefixSizeInBytes + params.HmacParams.TagSize + 2
	if params.CiphertextSegmentSize < minSegmentSize {
		return fmt.Errorf("ciphertext segment size must be at least (derivedKeySize + noncePrefixInBytes + tagSizeInBytes + 2)")
	}
	return nil
}
