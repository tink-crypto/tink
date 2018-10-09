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
	keyManagersMu sync.RWMutex
	keyManagers   = make(map[string]KeyManager) // typeURL -> KeyManager
)

// RegisterKeyManager registers the given key manager.
// Does not allow to overwrite existing key managers.
func RegisterKeyManager(km KeyManager) error {
	keyManagersMu.Lock()
	defer keyManagersMu.Unlock()
	typeURL := km.TypeURL()
	if _, existed := keyManagers[typeURL]; existed {
		return fmt.Errorf("tink.RegisterKeyManager: type %s already registered", typeURL)
	}
	keyManagers[typeURL] = km
	return nil
}

// GetKeyManager returns the key manager for the given typeURL if existed.
func GetKeyManager(typeURL string) (KeyManager, error) {
	keyManagersMu.RLock()
	defer keyManagersMu.RUnlock()
	km, existed := keyManagers[typeURL]
	if !existed {
		return nil, fmt.Errorf("tink.GetKeyManager: unsupported key type: %s", typeURL)
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
