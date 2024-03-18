// Copyright 2019 Google LLC
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

// Package registry provides a container that for each supported key type holds
// a corresponding KeyManager object, which can generate new keys or
// instantiate the primitive corresponding to given key.
//
// Registry is initialized at startup, and is later used to instantiate
// primitives for given keys or keysets. Keeping KeyManagers for all primitives
// in a single Registry (rather than having a separate KeyManager per
// primitive) enables modular construction of compound primitives from "simple"
// ones, e.g., AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
//
// Note that regular users will usually not work directly with Registry, but
// rather via primitive factories, which in the background query the Registry
// for specific KeyManagers. Registry is public though, to enable
// configurations with custom primitives and KeyManagers.
package registry

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var (
	keyManagersMu sync.RWMutex
	keyManagers   = make(map[string]KeyManager) // typeURL -> KeyManager
	kmsClientsMu  sync.RWMutex
	kmsClients    = []KMSClient{}
)

// RegisterKeyManager registers the given key manager.
// Does not allow to overwrite existing key managers.
func RegisterKeyManager(keyManager KeyManager) error {
	keyManagersMu.Lock()
	defer keyManagersMu.Unlock()
	typeURL := keyManager.TypeURL()
	if _, existed := keyManagers[typeURL]; existed {
		return fmt.Errorf("registry.RegisterKeyManager: type %s already registered", typeURL)
	}
	keyManagers[typeURL] = keyManager
	return nil
}

// GetKeyManager returns the key manager for the given typeURL if existed.
func GetKeyManager(typeURL string) (KeyManager, error) {
	keyManagersMu.RLock()
	defer keyManagersMu.RUnlock()
	keyManager, existed := keyManagers[typeURL]
	if !existed {
		return nil, fmt.Errorf("registry.GetKeyManager: unsupported key type: %s", typeURL)
	}
	return keyManager, nil
}

// NewKeyData generates a new KeyData for the given key template.
func NewKeyData(template *tinkpb.KeyTemplate) (*tinkpb.KeyData, error) {
	if template == nil {
		return nil, fmt.Errorf("registry.NewKeyData: invalid key template")
	}
	keyManager, err := GetKeyManager(template.TypeUrl)
	if err != nil {
		return nil, err
	}
	return keyManager.NewKeyData(template.Value)
}

// NewKey generates a new key for the given key template.
//
// Deprecated: use [NewKeyData] instead.
func NewKey(template *tinkpb.KeyTemplate) (proto.Message, error) {
	if template == nil {
		return nil, fmt.Errorf("registry.NewKey: invalid key template")
	}
	keyManager, err := GetKeyManager(template.TypeUrl)
	if err != nil {
		return nil, err
	}
	return keyManager.NewKey(template.Value)
}

// PrimitiveFromKeyData creates a new primitive for the key given in the given KeyData.
// Note that the returned primitive does not add/remove the output prefix.
// It is the caller's responsibility to handle this correctly, based on the key's output_prefix_type.
func PrimitiveFromKeyData(keyData *tinkpb.KeyData) (any, error) {
	if keyData == nil {
		return nil, fmt.Errorf("registry.PrimitiveFromKeyData: invalid key data")
	}
	return Primitive(keyData.TypeUrl, keyData.Value)
}

// Primitive creates a new primitive for the given serialized key using the KeyManager
// identified by the given typeURL.
// Note that the returned primitive does not add/remove the output prefix.
// It is the caller's responsibility to handle this correctly, based on the key's output_prefix_type.
func Primitive(typeURL string, serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("registry.Primitive: invalid serialized key")
	}
	keyManager, err := GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	return keyManager.Primitive(serializedKey)
}

// RegisterKMSClient is used to register a new KMS client.
//
// This function adds an object to a global list. It should only be called on
// startup.
//
// In many cases, registering a KMS client is not needed. Instead, call
// kmsClient.GetAEAD to get a remote AEAD, and then use it to encrypt
// a keyset with keyset.Write, or to create an envelope AEAD using
// aead.NewKMSEnvelopeAEAD2.
func RegisterKMSClient(kmsClient KMSClient) {
	kmsClientsMu.Lock()
	defer kmsClientsMu.Unlock()
	kmsClients = append(kmsClients, kmsClient)
}

// GetKMSClient fetches a KMSClient by a given URI.
func GetKMSClient(keyURI string) (KMSClient, error) {
	kmsClientsMu.RLock()
	defer kmsClientsMu.RUnlock()
	for _, kmsClient := range kmsClients {
		if kmsClient.Supported(keyURI) {
			return kmsClient, nil
		}
	}
	return nil, fmt.Errorf("KMS client supporting %s not found", keyURI)
}

// ClearKMSClients removes all registered KMS clients.
//
// Should only be used in tests.
func ClearKMSClients() {
	kmsClientsMu.Lock()
	defer kmsClientsMu.Unlock()
	kmsClients = []KMSClient{}
}
