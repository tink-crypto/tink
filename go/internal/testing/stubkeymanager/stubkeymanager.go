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

// Package stubkeymanager defines key managers for testing primitives.
package stubkeymanager

import (
	"io"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalregistry"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// StubKeyManager is a key manager for testing.
type StubKeyManager struct {
	URL     string
	Prim    interface{}
	Key     proto.Message
	KeyData *tinkpb.KeyData
}

var _ (registry.KeyManager) = (*StubKeyManager)(nil)

// Primitive returns the stub primitive.
func (km *StubKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	return km.Prim, nil
}

// NewKey returns the stub Key.
func (km *StubKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return km.Key, nil
}

// NewKeyData returns the stub KeyData.
func (km *StubKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return km.KeyData, nil
}

// DoesSupport returns true if this KeyManager supports key type identified by typeURL.
func (km *StubKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == km.URL
}

// TypeURL returns the stub type url.
func (km *StubKeyManager) TypeURL() string {
	return km.URL
}

// StubPrivateKeyManager is a private key manager for testing.
type StubPrivateKeyManager struct {
	StubKeyManager
	PubKeyData *tinkpb.KeyData
}

var _ (registry.PrivateKeyManager) = (*StubPrivateKeyManager)(nil)

// PublicKeyData returns the stub public key data.
func (skm *StubPrivateKeyManager) PublicKeyData(serializedKey []byte) (*tinkpb.KeyData, error) {
	return skm.PubKeyData, nil
}

// StubDerivableKeyManager is a derivable key manager for testing.
type StubDerivableKeyManager struct {
	StubKeyManager
	KeyMatType tinkpb.KeyData_KeyMaterialType
	DerKey     proto.Message
	DerErr     error
}

var _ (internalregistry.DerivableKeyManager) = (*StubDerivableKeyManager)(nil)

// KeyMaterialType returns the stub key material type.
func (dkm *StubDerivableKeyManager) KeyMaterialType() tinkpb.KeyData_KeyMaterialType {
	return dkm.KeyMatType
}

// DeriveKey returns the stub derived key and error.
func (dkm *StubDerivableKeyManager) DeriveKey(serializedKeyFormat []byte, pseudorandomness io.Reader) (proto.Message, error) {
	return dkm.DerKey, dkm.DerErr
}
