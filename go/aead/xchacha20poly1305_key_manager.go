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

package aead

import (
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"

	tpb "github.com/google/tink/go/proto/tink_go_proto"
	xpb "github.com/google/tink/go/proto/xchacha20_poly1305_go_proto"
)

const (
	xChaCha20Poly1305KeyVersion = 0
	xChaCha20Poly1305TypeURL    = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"
)

var (
	errInvalidXChaCha20Poly1305Key       = fmt.Errorf("xchacha20poly1305_key_manager: invalid key")
	errInvalidXChaCha20Poly1305KeyFormat = fmt.Errorf("xchacha20poly1305_key_manager: invalid key format")
)

// xChaCha20Poly1305KeyManager generates XChaCha20Poly1305Key keys and produces
// instances of XChaCha20Poly1305.
type xChaCha20Poly1305KeyManager struct{}

// Assert that xChaCha20Poly1305KeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*xChaCha20Poly1305KeyManager)(nil)

// Primitive constructs a XChaCha20Poly1305 for the given serialized
// XChaCha20Poly1305Key.
func (km *xChaCha20Poly1305KeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidXChaCha20Poly1305Key
	}
	key := new(xpb.XChaCha20Poly1305Key)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidXChaCha20Poly1305Key
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	ret, err := subtle.NewXChaCha20Poly1305(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: cannot create new primitive: %v", err)
	}
	return ret, nil
}

// NewKey generates a new XChaCha20Poly1305Key. It ignores serializedKeyFormat
// because the key size and other params are fixed.
func (km *xChaCha20Poly1305KeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return &xpb.XChaCha20Poly1305Key{
		Version:  xChaCha20Poly1305KeyVersion,
		KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
	}, nil
}

// NewKeyData generates a new KeyData. It ignores serializedKeyFormat because
// the key size and other params are fixed. This should be used solely by the
// key management API.
func (km *xChaCha20Poly1305KeyManager) NewKeyData(serializedKeyFormat []byte) (*tpb.KeyData, error) {
	key := &xpb.XChaCha20Poly1305Key{
		Version:  xChaCha20Poly1305KeyVersion,
		KeyValue: random.GetRandomBytes(chacha20poly1305.KeySize),
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tpb.KeyData{
		TypeUrl:         xChaCha20Poly1305TypeURL,
		Value:           serializedKey,
		KeyMaterialType: km.KeyMaterialType(),
	}, nil
}

// DoesSupport checks whether this key manager supports the given key type.
func (km *xChaCha20Poly1305KeyManager) DoesSupport(typeURL string) bool {
	return typeURL == xChaCha20Poly1305TypeURL
}

// TypeURL returns the type URL of keys managed by this key manager.
func (km *xChaCha20Poly1305KeyManager) TypeURL() string {
	return xChaCha20Poly1305TypeURL
}

// KeyMaterialType returns the key material type of this key manager.
func (km *xChaCha20Poly1305KeyManager) KeyMaterialType() tpb.KeyData_KeyMaterialType {
	return tpb.KeyData_SYMMETRIC
}

// DeriveKey derives a new key from serializedKeyFormat and pseudorandomness.
// Unlike NewKey, DeriveKey validates serializedKeyFormat's version.
func (km *xChaCha20Poly1305KeyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	keyFormat := new(xpb.XChaCha20Poly1305KeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}
	err := keyset.ValidateKeyVersion(keyFormat.Version, xChaCha20Poly1305KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}

	keyValue := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(pseudorandomness, keyValue); err != nil {
		return nil, fmt.Errorf("xchacha20poly1305_key_manager: not enough pseudorandomness given")
	}
	return &xpb.XChaCha20Poly1305Key{
		Version:  xChaCha20Poly1305KeyVersion,
		KeyValue: keyValue,
	}, nil
}

// validateKey validates the given XChaCha20Poly1305Key.
func (km *xChaCha20Poly1305KeyManager) validateKey(key *xpb.XChaCha20Poly1305Key) error {
	err := keyset.ValidateKeyVersion(key.Version, xChaCha20Poly1305KeyVersion)
	if err != nil {
		return fmt.Errorf("xchacha20poly1305_key_manager: %v", err)
	}
	keySize := uint32(len(key.KeyValue))
	if keySize != chacha20poly1305.KeySize {
		return fmt.Errorf("xchacha20poly1305_key_manager: key size != %d", chacha20poly1305.KeySize)
	}
	return nil
}
