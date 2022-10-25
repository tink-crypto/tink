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

package internalregistry

import (
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	derivableKeyManagersMu sync.RWMutex

	// derivableKeyManagers is the set of all key managers allowed to derive keys.
	// It is keyed by the key manager's type URL, i.e. typeURL -> true. All type
	// URLs in this map correspond to key managers that are
	//   - in the registry and
	//   - implement key derivation.
	//
	// This exists because of Golang's weak type system and the desire to keep key
	// derivation non-public. If we do not explicitly restrict derivable key
	// managers, users would be able to register any custom key manager that
	// implements DeriveKey() and be able to derive keys with it, even without
	// access to this library, internalregistry.
	derivableKeyManagers = make(map[string]bool)
)

// AllowKeyDerivation adds the type URL to derivableKeyManagers if the
// corresponding key manager is in the registry and implements key derivation.
func AllowKeyDerivation(typeURL string) error {
	km, err := registry.GetKeyManager(typeURL)
	if err != nil {
		return err
	}
	if _, ok := km.(DerivableKeyManager); !ok {
		return fmt.Errorf("key manager for type %s does not implement key derivation", typeURL)
	}
	derivableKeyManagersMu.Lock()
	derivableKeyManagers[typeURL] = true
	derivableKeyManagersMu.Unlock()
	return nil
}

// CanDeriveKeys returns true if typeURL is in derivableKeyManagers.
func CanDeriveKeys(typeURL string) bool {
	derivableKeyManagersMu.Lock()
	defer derivableKeyManagersMu.Unlock()
	return derivableKeyManagers[typeURL]
}

// DeriveKey derives a new key from template and pseudorandomness.
func DeriveKey(keyTemplate *tinkpb.KeyTemplate, pseudorandomness io.Reader) (*tinkpb.KeyData, error) {
	if !CanDeriveKeys(keyTemplate.GetTypeUrl()) {
		return nil, fmt.Errorf("key manager for type %s is not allowed to derive keys", keyTemplate.GetTypeUrl())
	}
	km, err := registry.GetKeyManager(keyTemplate.GetTypeUrl())
	if err != nil {
		return nil, err
	}
	keyManager, ok := km.(DerivableKeyManager)
	if !ok {
		return nil, fmt.Errorf("key manager for type %s does not implement key derivation", keyTemplate.GetTypeUrl())
	}
	key, err := keyManager.DeriveKey(keyTemplate.GetValue(), pseudorandomness)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize derived key: %v", err)
	}
	return &tinkpb.KeyData{
		TypeUrl:         keyTemplate.GetTypeUrl(),
		Value:           serializedKey,
		KeyMaterialType: keyManager.KeyMaterialType(),
	}, nil
}
