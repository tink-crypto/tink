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

package jwt

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	macsubtle "github.com/google/tink/go/mac/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	jwtmacpb "github.com/google/tink/go/proto/jwt_hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtHMACKeyVersion = 0
	jwtHMACTypeURL    = "type.googleapis.com/google.crypto.tink.JwtHmacKey"
)

// jwtHMACKeyManager is an implementation of the KeyManager interface
type jwtHMACKeyManager struct{}

// Assert that jwtHMACKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*jwtHMACKeyManager)(nil)

var hsAlgToHash = map[jwtmacpb.JwtHmacAlgorithm]string{
	jwtmacpb.JwtHmacAlgorithm_HS256: "SHA256",
	jwtmacpb.JwtHmacAlgorithm_HS384: "SHA384",
	jwtmacpb.JwtHmacAlgorithm_HS512: "SHA512",
}

var hsAlgToMinKeySizeBytes = map[jwtmacpb.JwtHmacAlgorithm]int{
	jwtmacpb.JwtHmacAlgorithm_HS256: 32,
	jwtmacpb.JwtHmacAlgorithm_HS384: 48,
	jwtmacpb.JwtHmacAlgorithm_HS512: 64,
}

func (km *jwtHMACKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	key := &jwtmacpb.JwtHmacKey{}
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, err
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	hashAlg, ok := hsAlgToHash[key.GetAlgorithm()]
	if !ok {
		return nil, fmt.Errorf("invalid algorithm: '%v'", key.GetAlgorithm())
	}
	tagSize, err := subtle.GetHashDigestSize(hashAlg)
	if err != nil {
		return nil, err
	}
	mac, err := macsubtle.NewHMAC(hashAlg, key.GetKeyValue(), tagSize)
	if err != nil {
		return nil, err
	}
	var kid *string = nil
	if key.GetCustomKid() != nil {
		k := key.GetCustomKid().GetValue()
		kid = &k
	}
	return newMACWithKID(mac, key.GetAlgorithm().String(), kid)
}

func (km *jwtHMACKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if serializedKeyFormat == nil || len(serializedKeyFormat) == 0 {
		return nil, fmt.Errorf("no serialized key format")
	}
	keyFormat := &jwtmacpb.JwtHmacKeyFormat{}
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, err
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, err
	}
	return &jwtmacpb.JwtHmacKey{
		Version:   jwtHMACKeyVersion,
		Algorithm: keyFormat.GetAlgorithm(),
		KeyValue:  random.GetRandomBytes(keyFormat.KeySize),
	}, nil
}

func (km *jwtHMACKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtHMACTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *jwtHMACKeyManager) DoesSupport(keyTypeURL string) bool {
	return jwtHMACTypeURL == keyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *jwtHMACKeyManager) TypeURL() string {
	return jwtHMACTypeURL
}

func (km *jwtHMACKeyManager) validateKey(key *jwtmacpb.JwtHmacKey) error {
	if key == nil {
		return fmt.Errorf("key can't be nil")
	}
	if err := keyset.ValidateKeyVersion(key.Version, jwtHMACKeyVersion); err != nil {
		return err
	}
	minKeySizeBytes, ok := hsAlgToMinKeySizeBytes[key.GetAlgorithm()]
	if !ok {
		return fmt.Errorf("invalid algorithm: '%v'", key.GetAlgorithm())
	}
	if len(key.KeyValue) < minKeySizeBytes {
		return fmt.Errorf("invalid JwtHmacKey: KeyValue is too short")
	}
	return nil
}

func (km *jwtHMACKeyManager) validateKeyFormat(keyFormat *jwtmacpb.JwtHmacKeyFormat) error {
	if keyFormat == nil {
		return fmt.Errorf("key format can't be nil")
	}
	minKeySizeBytes, ok := hsAlgToMinKeySizeBytes[keyFormat.GetAlgorithm()]
	if !ok {
		return fmt.Errorf("invalid algorithm: '%v'", keyFormat.GetAlgorithm())
	}
	if int(keyFormat.KeySize) < minKeySizeBytes {
		return fmt.Errorf("invalid JwtHmacKeyFormat: KeySize is too small")
	}
	return nil
}
