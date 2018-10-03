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

var (
	keyManagers = newKeyManagerMap()
)

type keyManagerMap struct {
	sync.RWMutex
	m map[string]KeyManager
}

func newKeyManagerMap() *keyManagerMap {
	kmMap := new(keyManagerMap)
	kmMap.m = make(map[string]KeyManager)
	return kmMap
}

// Get returns whether the specified typeURL exists in the map and the corresponding value if it
// exists.
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

// RegisterKeyManager registers the given key manager, and does nothing if there already exists a key manager with the same typeURL.
func RegisterKeyManager(km KeyManager) error {
	if km == nil {
		return fmt.Errorf("registry: km must be non null")
	}
	typeURL := km.TypeURL()
	// try to get the key manager with the given typeURL, return nil if there is
	_, existed := keyManagers.Get(typeURL)
	if existed {
		return nil
	}
	// add the manager
	keyManagers.Put(typeURL, km)
	return nil
}

// GetKeyManager returns the key manager for the given typeURL if existed.
func GetKeyManager(typeURL string) (KeyManager, error) {
	km, existed := keyManagers.Get(typeURL)
	if !existed {
		return nil, fmt.Errorf("registry: unsupported key type: %s", typeURL)
	}
	return km, nil
}

// NewKeyData generates a new KeyData for the given key template.
func NewKeyData(kt *tinkpb.KeyTemplate) (*tinkpb.KeyData, error) {
	if kt == nil {
		return nil, fmt.Errorf("registry: invalid key template")
	}
	km, err := GetKeyManager(kt.TypeUrl)
	if err != nil {
		return nil, err
	}
	return km.NewKeyData(kt.Value)
}

// NewKey generates a new key for the given key template.
func NewKey(kt *tinkpb.KeyTemplate) (proto.Message, error) {
	if kt == nil {
		return nil, fmt.Errorf("registry: invalid key template")
	}
	km, err := GetKeyManager(kt.TypeUrl)
	if err != nil {
		return nil, err
	}
	return km.NewKey(kt.Value)
}

// PrimitiveFromKeyData creates a new primitive for the key given in the given KeyData.
func PrimitiveFromKeyData(kd *tinkpb.KeyData) (interface{}, error) {
	if kd == nil {
		return nil, fmt.Errorf("registry: invalid key data")
	}
	return Primitive(kd.TypeUrl, kd.Value)
}

// Primitive creates a new primitive for the given serialized key using the KeyManager
// identified by the given typeURL.
func Primitive(typeURL string, sk []byte) (interface{}, error) {
	if len(sk) == 0 {
		return nil, fmt.Errorf("registry: invalid serialized key")
	}
	km, err := GetKeyManager(typeURL)
	if err != nil {
		return nil, err
	}
	return km.Primitive(sk)
}

// Primitives creates a set of primitives corresponding to the keys with
// status=ENABLED in the keyset of the given keyset handle, assuming all the
// corresponding key managers are present (keys with status!=ENABLED are skipped).
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
func Primitives(kh *KeysetHandle) (*PrimitiveSet, error) {
	return PrimitivesWithKeyManager(kh, nil)
}

// PrimitivesWithKeyManager creates a set of primitives corresponding to
// the keys with status=ENABLED in the keyset of the given keysetHandle, using
// the given key manager (instead of registered key managers) for keys supported
// by it.  Keys not supported by the key manager are handled by matching registered
// key managers (if present), and keys with status!=ENABLED are skipped.
//
// This enables custom treatment of keys, for example providing extra context
// (e.g. credentials for accessing keys managed by a KMS), or gathering custom
// monitoring/profiling information.
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
func PrimitivesWithKeyManager(kh *KeysetHandle, km KeyManager) (*PrimitiveSet, error) {
	if kh == nil {
		return nil, fmt.Errorf("registry: invalid keyset handle")
	}
	keyset := kh.Keyset()
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
		if km != nil && km.DoesSupport(key.KeyData.TypeUrl) {
			primitive, err = km.Primitive(key.KeyData.Value)
		} else {
			primitive, err = PrimitiveFromKeyData(key.KeyData)
		}
		if err != nil {
			return nil, fmt.Errorf("registry: cannot get primitive from key: %s", err)
		}
		entry, err := primitiveSet.Add(primitive, key)
		if err != nil {
			return nil, fmt.Errorf("registry: cannot add primitive: %s", err)
		}
		if key.KeyId == keyset.PrimaryKeyId {
			primitiveSet.Primary = entry
		}
	}
	return primitiveSet, nil
}
