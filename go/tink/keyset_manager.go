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

	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// KeysetManager manages a Keyset-proto, with convenience methods that rotate, disable, enable or destroy keys.
// Note: It is not thread-safe.
type KeysetManager struct {
	ks *tinkpb.Keyset
}

// NewKeysetManager creates a new instance with an empty Keyset.
func NewKeysetManager() *KeysetManager {
	ret := new(KeysetManager)
	ret.ks = new(tinkpb.Keyset)
	return ret
}

// FromKeysetHandle creates a new instance from the given KeysetHandle.
func FromKeysetHandle(kh *KeysetHandle) *KeysetManager {
	ret := new(KeysetManager)
	ret.ks = kh.ks
	return ret
}

// Rotate generates a fresh key using the given key template and
// sets the new key as the primary key.
func (km *KeysetManager) Rotate(kt *tinkpb.KeyTemplate) error {
	if kt == nil {
		return fmt.Errorf("keyset_manager: cannot rotate, need key template")
	}
	keyData, err := NewKeyData(kt)
	if err != nil {
		return fmt.Errorf("keyset_manager: cannot create KeyData: %s", err)
	}
	keyID := km.newKeyID()
	outputPrefixType := kt.OutputPrefixType
	if outputPrefixType == tinkpb.OutputPrefixType_UNKNOWN_PREFIX {
		outputPrefixType = tinkpb.OutputPrefixType_TINK
	}
	key := &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            keyID,
		OutputPrefixType: outputPrefixType,
	}
	// Set the new key as the primary key
	km.ks.Key = append(km.ks.Key, key)
	km.ks.PrimaryKeyId = keyID
	return nil
}

// KeysetHandle creates a new KeysetHandle for the managed keyset.
func (km *KeysetManager) KeysetHandle() (*KeysetHandle, error) {
	return &KeysetHandle{km.ks}, nil
}

// newKeyID generates a key id that has not been used by any key in the keyset.
func (km *KeysetManager) newKeyID() uint32 {
	for {
		ret := random.GetRandomUint32()
		ok := true
		for _, key := range km.ks.Key {
			if key.KeyId == ret {
				ok = false
				break
			}
		}
		if ok {
			return ret
		}
	}
}
