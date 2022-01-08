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
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/ed25519"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature/subtle"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	ed25519SignerKeyVersion = 0
	ed25519SignerTypeURL    = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
)

// common errors
var errInvalidED25519SignKey = errors.New("ed25519_signer_key_manager: invalid key")
var errInvalidED25519SignKeyFormat = errors.New("ed25519_signer_key_manager: invalid key format")

// ed25519SignerKeyManager is an implementation of KeyManager interface.
// It generates new ED25519PrivateKeys and produces new instances of ED25519Sign subtle.
type ed25519SignerKeyManager struct{}

// Primitive creates an ED25519Sign subtle for the given serialized ED25519PrivateKey proto.
func (km *ed25519SignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidED25519SignKey
	}
	key := new(ed25519pb.Ed25519PrivateKey)

	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidED25519SignKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}

	ret, err := subtle.NewED25519Signer(key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("ed25519_signer_key_manager: %s", err)
	}
	return ret, nil
}

// NewKey creates a new ED25519PrivateKey according to specification the given serialized ED25519KeyFormat.
func (km *ed25519SignerKeyManager) NewKey(serializedKey []byte) (proto.Message, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519_signer_key_manager: cannot generate ED25519 key: %s", err)
	}

	publicProto := &ed25519pb.Ed25519PublicKey{
		Version:  ed25519SignerKeyVersion,
		KeyValue: public,
	}
	privateProto := &ed25519pb.Ed25519PrivateKey{
		Version:   ed25519SignerKeyVersion,
		PublicKey: publicProto,
		KeyValue:  private.Seed(),
	}
	return privateProto, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ED25519KeyFormat. It should be used solely by the key management API.
func (km *ed25519SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidED25519SignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         ed25519SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *ed25519SignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ed25519pb.Ed25519PrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidED25519SignKey
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidED25519SignKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         ed25519VerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ed25519SignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ed25519SignerTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ed25519SignerKeyManager) TypeURL() string {
	return ed25519SignerTypeURL
}

// validateKey validates the given ED25519PrivateKey.
func (km *ed25519SignerKeyManager) validateKey(key *ed25519pb.Ed25519PrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, ed25519SignerKeyVersion); err != nil {
		return fmt.Errorf("ed25519_signer_key_manager: invalid key: %s", err)
	}
	if len(key.KeyValue) != ed25519.SeedSize {
		return fmt.Errorf("ed2219_signer_key_manager: invalid key length, got %d", len(key.KeyValue))
	}
	return nil
}
