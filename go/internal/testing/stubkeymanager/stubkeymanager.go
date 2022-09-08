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

// Package stubkeymanager defines a key manager for testing primitives.
package stubkeymanager

import (
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
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
