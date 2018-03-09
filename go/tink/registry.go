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

package tink

import (
	"fmt"
	"sync"

	"github.com/golang/protobuf/proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// Mapping between typeURL and KeyManager.
// Using mutex for concurrency read and write
type keyManagerMap struct {
	sync.RWMutex
	m map[string]KeyManager
}

// NewKeyManagerMap creates a new instance of keyManagerMap.
func NewKeyManagerMap() *keyManagerMap {
	kmMap := new(keyManagerMap)
	kmMap.m = make(map[string]KeyManager)
	return kmMap
}

// Get returns whether the specified typeURL exists in the map and
// the corresponding value if it exists.
func (kmMap *keyManagerMap) Get(typeURL string) (KeyManager, bool) {
	kmMap.RLock()
	defer kmMap.RUnlock()
	km, existed := kmMap.m[typeURL]
	return km, existed
}

// Put associates the given keyManager with the given typeURL in the map.
func (kmMap *keyManagerMap) Put(typeURL string, keyManager KeyManager) {
	kmMap.Lock()
	defer kmMap.Unlock()
	kmMap.m[typeURL] = keyManager
}

// Registry for KeyMangers. <p>
// It is essentially a big container (map) that for each supported key type holds
// a corresponding KeyManager object, which "understands" the key type (i.e. the KeyManager
// can instantiate the primitive corresponding to given key, or can generate new keys
// of the supported key type).  Registry is initialized at startup, and is later
// used to instantiate primitives for given keys or keysets.  Keeping KeyManagers for all
// primitives in a single Registry (rather than having a separate KeyManager per primitive)
// enables modular construction of compound primitives from "simple" ones, e.g.,
// AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC. <p>
//
// Note that regular users will usually not work directly with Registry, but rather
// via primitive factories, which in the background query the Registry for specific
// KeyManagers. Registry is public though, to enable configurations with custom
// primitives and KeyManagers.
type registry struct {
	// Thread-safe mapping between typeURL and KeyManager.
	keyManagers *keyManagerMap
}

// newRegistry creates a new instance of registry.
func newRegistry() *registry {
	reg := new(registry)
	reg.keyManagers = NewKeyManagerMap()
	return reg
}

// registryInstance is a shared instance of registry. It is initialized only once
// via function Registry().
var registryInstance *registry
var once sync.Once

// Registry creates an instance of registry if there isn't and returns the instance.
func Registry() *registry {
	// only create the registry instance once
	once.Do(func() {
		registryInstance = newRegistry()
	})
	return registryInstance
}

// RegisterKeyManager registers the given key manager.
// It does nothing if there already exists a key manager with the same type url.
// It returns true if the key manager is registered; false otherwise.
func (reg *registry) RegisterKeyManager(manager KeyManager) (bool, error) {
	if manager == nil {
		return false, fmt.Errorf("registry: invalid key manager")
	}
	typeURL := manager.GetKeyType()
	// try to get the key manager with the given typeURL, return false if there is
	_, existed := reg.keyManagers.Get(typeURL)
	if existed {
		return false, nil
	}
	// add the manager
	reg.keyManagers.Put(typeURL, manager)
	return true, nil
}

// GetKeyManager returns the key manager for the given type url if existed.
func (reg *registry) GetKeyManager(typeURL string) (KeyManager, error) {
	manager, existed := reg.keyManagers.Get(typeURL)
	if !existed {
		return nil, fmt.Errorf("registry: unsupported key type: %s", typeURL)
	}
	return manager, nil
}

// NewKeyData generates a new KeyData for the given KeyTemplate.
func (reg *registry) NewKeyData(template *tinkpb.KeyTemplate) (*tinkpb.KeyData, error) {
	if template == nil {
		return nil, fmt.Errorf("registry: invalid key template")
	}
	manager, err := reg.GetKeyManager(template.TypeUrl)
	if err != nil {
		return nil, err
	}
	return manager.NewKeyData(template.Value)
}

// NewKeyFromKeyTemplate generates a new key for the given KeyTemplate.
func (reg *registry) NewKeyFromKeyTemplate(template *tinkpb.KeyTemplate) (proto.Message, error) {
	if template == nil {
		return nil, fmt.Errorf("registry: invalid key template")
	}
	manager, err := reg.GetKeyManager(template.TypeUrl)
	if err != nil {
		return nil, err
	}
	return manager.NewKeyFromSerializedKeyFormat(template.Value)
}

// NewKeyFromKeyFormat generates a new key for the given KeyFormat using the
// KeyManager identified by the given typeURL.
func (reg *registry) NewKeyFromKeyFormat(typeURL string,
	format proto.Message) (proto.Message, error) {
	manager, err := reg.GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	return manager.NewKeyFromKeyFormat(format)
}

// GetPrimitiveFromKey creates a new primitive for the given key using the KeyManager
// identified by the given typeURL.
func (reg *registry) GetPrimitiveFromKey(typeURL string,
	key proto.Message) (interface{}, error) {
	manager, err := reg.GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	return manager.GetPrimitiveFromKey(key)
}

// GetPrimitiveFromKeyData creates a new primitive for the key given in the given KeyData.
func (reg *registry) GetPrimitiveFromKeyData(keyData *tinkpb.KeyData) (interface{}, error) {
	if keyData == nil {
		return nil, fmt.Errorf("registry: invalid key data")
	}
	return reg.GetPrimitiveFromSerializedKey(keyData.TypeUrl, keyData.Value)
}

// GetPrimitiveFromSerializedKey creates a new primitive for the given serialized key
// using the KeyManager identified by the given typeURL.
func (reg *registry) GetPrimitiveFromSerializedKey(typeURL string,
	serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, fmt.Errorf("registry: invalid serialized key")
	}
	manager, err := reg.GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	return manager.GetPrimitiveFromSerializedKey(serializedKey)
}

// GetPrimitives creates a set of primitives corresponding to the keys with
// status=ENABLED in the keyset of the given keysetHandle, assuming all the
// corresponding key managers are present (keys with status!=ENABLED are skipped).
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
func (reg *registry) GetPrimitives(keysetHandle *KeysetHandle) (*PrimitiveSet, error) {
	return reg.GetPrimitivesWithCustomManager(keysetHandle, nil)
}

// GetPrimitivesWithCustomManager creates a set of primitives corresponding to
// the keys with status=ENABLED in the keyset of the given keysetHandle, using
// the given customManager (instead of registered key managers) for keys supported
// by it.  Keys not supported by the customManager are handled by matching registered
// key managers (if present), and keys with status!=ENABLED are skipped. <p>
//
// This enables custom treatment of keys, for example providing extra context
// (e.g. credentials for accessing keys managed by a KMS), or gathering custom
// monitoring/profiling information.
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
func (reg *registry) GetPrimitivesWithCustomManager(
	keysetHandle *KeysetHandle, customManager KeyManager) (*PrimitiveSet, error) {
	// TODO(thaidn): check that all keys are of the same primitive
	if keysetHandle == nil {
		return nil, fmt.Errorf("registry: invalid keyset handle")
	}
	keyset := keysetHandle.Keyset()
	if err := ValidateKeyset(keyset); err != nil {
		return nil, fmt.Errorf("registry: invalid keyset: %s", err)
	}
	primitiveSet := NewPrimitiveSet()
	for _, key := range keyset.Key {
		if key.Status != tinkpb.KeyStatusType_ENABLED {
			continue
		}
		var primitive interface{}
		var err error
		if customManager != nil && customManager.DoesSupport(key.KeyData.TypeUrl) {
			primitive, err = customManager.GetPrimitiveFromSerializedKey(key.KeyData.Value)
		} else {
			primitive, err = reg.GetPrimitiveFromKeyData(key.KeyData)
		}
		if err != nil {
			return nil, fmt.Errorf("registry: cannot get primitive from key: %s", err)
		}
		entry, err := primitiveSet.AddPrimitive(primitive, key)
		if err != nil {
			return nil, fmt.Errorf("registry: cannot add primitive: %s", err)
		}
		if key.KeyId == keyset.PrimaryKeyId {
			primitiveSet.SetPrimary(entry)
		}
	}
	return primitiveSet, nil
}

// GetPublicKeyData is Convenience method for extracting the public key data
// from the given serialized private key. It looks up a PrivateKeyManager
// identified by the given typeURL, and calls the manager's GetPublicKeyData() method.
func (reg *registry) GetPublicKeyData(typeURL string,
	serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	keyManager, err := reg.GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	privateKeyManager, ok := keyManager.(PrivateKeyManager)
	if !ok {
		return nil, fmt.Errorf("registry: %s is not belong to a PrivateKeyManager", typeURL)
	}
	return privateKeyManager.GetPublicKeyData(serializedPrivKey)
}
