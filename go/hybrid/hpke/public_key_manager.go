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

package hpke

import (
	"errors"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	hpkepb "github.com/google/tink/go/proto/hpke_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	publicKeyKeyVersion = 0
	publicKeyTypeURL    = "type.googleapis.com/google.crypto.tink.HpkePublicKey"
)

var (
	errInvalidPublicKey = errors.New("invalid HPKE public key")
	errNotSupported     = errors.New("not supported on HPKE public key manager")
)

// publicKeyManager implements the KeyManager interface for HybridEncrypt.
type publicKeyManager struct{}

var _ registry.KeyManager = (*publicKeyManager)(nil)

func (p *publicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidPublicKey
	}
	key := new(hpkepb.HpkePublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidPublicKey
	}
	if err := keyset.ValidateKeyVersion(key.GetVersion(), publicKeyKeyVersion); err != nil {
		return nil, err
	}
	return newEncrypt(key)
}

func (p *publicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == publicKeyTypeURL
}

func (p *publicKeyManager) TypeURL() string {
	return publicKeyTypeURL
}

func (p *publicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errNotSupported
}

func (p *publicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errNotSupported
}
