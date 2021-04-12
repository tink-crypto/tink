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

package signature

import (
	"fmt"

	"golang.org/x/crypto/ed25519"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature/subtle"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	ed25519VerifierKeyVersion = 0
	ed25519VerifierTypeURL    = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
)

// common errors
var errInvalidED25519VerifierKey = fmt.Errorf("ed25519_verifier_key_manager: invalid key")
var errED25519VerifierNotImplemented = fmt.Errorf("ed25519_verifier_key_manager: not implemented")

// ed25519VerifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type ed25519VerifierKeyManager struct{}

// newED25519VerifierKeyManager creates a new ed25519VerifierKeyManager.
func newED25519VerifierKeyManager() *ed25519VerifierKeyManager {
	return new(ed25519VerifierKeyManager)
}

// Primitive creates an ED25519Verifier subtle for the given serialized ED25519PublicKey proto.
func (km *ed25519VerifierKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidED25519VerifierKey
	}
	key := new(ed25519pb.Ed25519PublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidED25519VerifierKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("ed25519_verifier_key_manager: %s", err)
	}
	ret, err := subtle.NewED25519Verifier(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("ed25519_verifier_key_manager: invalid key: %s", err)
	}
	return ret, nil
}

// NewKey is not implemented.
func (km *ed25519VerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errED25519VerifierNotImplemented
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ED25519KeyFormat. It should be used solely by the key management API.
func (km *ed25519VerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errED25519VerifierNotImplemented
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ed25519VerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ed25519VerifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ed25519VerifierKeyManager) TypeURL() string {
	return ed25519VerifierTypeURL
}

// validateKey validates the given ED25519PublicKey.
func (km *ed25519VerifierKeyManager) validateKey(key *ed25519pb.Ed25519PublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, ed25519VerifierKeyVersion); err != nil {
		return fmt.Errorf("ed25519_verifier_key_manager: %s", err)
	}
	if len(key.KeyValue) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519_verifier_key_manager: invalid key length, required :%d", ed25519.PublicKeySize)
	}
	return nil
}
