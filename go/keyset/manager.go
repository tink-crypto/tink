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

package keyset

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/subtle/random"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// Manager manages a Keyset-proto, with convenience methods that rotate, disable, enable or destroy keys.
// Note: It is not thread-safe.
type Manager struct {
	ks *tinkpb.Keyset
}

// NewManager creates a new instance with an empty Keyset.
func NewManager() *Manager {
	ret := new(Manager)
	ret.ks = new(tinkpb.Keyset)
	return ret
}

// NewManagerFromHandle creates a new instance from the given Handle.
func NewManagerFromHandle(kh *Handle) *Manager {
	ret := new(Manager)
	ret.ks = kh.ks
	return ret
}

// Rotate generates a fresh key using the given key template and
// sets the new key as the primary key.
//
// Deprecated: please use Add instead. Rotate adds a new key and immediately promotes it to primary.
// However, when you do keyset rotation, you almost never want to make the new key primary,
// because old binaries don't know the new key yet.
func (km *Manager) Rotate(kt *tinkpb.KeyTemplate) error {
	keyID, err := km.add(kt)
	if err != nil {
		return err
	}
	// Set the new key as the primary key
	km.ks.PrimaryKeyId = keyID
	return nil
}

// Add generates and adds a fresh key using the given key template.
// the key is enabled on creation, but not set to primary.
func (km *Manager) Add(kt *tinkpb.KeyTemplate) error {
	_, err := km.add(kt)
	return err
}

// add will generate and add a fresh key generated with the given key template
// and return the id of the generated key
func (km *Manager) add(kt *tinkpb.KeyTemplate) (uint32, error) {
	if kt == nil {
		return 0, errors.New("keyset_manager: cannot add key, need key template")
	}
	if kt.OutputPrefixType == tinkpb.OutputPrefixType_UNKNOWN_PREFIX {
		return 0, errors.New("keyset_manager: unknown output prefix type")
	}
	if km.ks == nil {
		return 0, errors.New("keyset_manager: cannot add key to nil keyset")
	}
	keyData, err := registry.NewKeyData(kt)
	if err != nil {
		return 0, fmt.Errorf("keyset_manager: cannot create KeyData: %s", err)
	}
	keyID := km.newKeyID()
	key := &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           tinkpb.KeyStatusType_ENABLED,
		KeyId:            keyID,
		OutputPrefixType: kt.OutputPrefixType,
	}
	km.ks.Key = append(km.ks.Key, key)
	return keyID, nil
}

// SetPrimary sets the key with given keyID as primary
// returns an error if the key is not found or not enabled
func (km *Manager) SetPrimary(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset_manager: cannot set primary, no keyset")
	}
	for _, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED {
			km.ks.PrimaryKeyId = keyID
			return nil
		}
		return errors.New("keyset_manager: cannot set key as primary because it's not enabled")

	}
	return fmt.Errorf("keyset_manager: key with id %d not found", keyID)
}

// Enable will enable the key with given keyID
// returns an error if the key is not found or is not enabled or disabled already
func (km *Manager) Enable(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset_manager: cannot enable key, no keyset")
	}
	for i, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED || key.Status == tinkpb.KeyStatusType_DISABLED {
			km.ks.Key[i].Status = tinkpb.KeyStatusType_ENABLED
			return nil
		}
		return fmt.Errorf("keyset_manager: cannot enable key with id %d with status %s", keyID, key.Status.String())
	}
	return fmt.Errorf("keyset_manager: key with id %d not found", keyID)
}

// Disable will disable the key with given keyID
// returns an error if the key is not found or it is the primary key
func (km *Manager) Disable(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset_manager: cannot disable key, no keyset")
	}
	if km.ks.PrimaryKeyId == keyID {
		return errors.New("keyset_manager: cannot disable the primary key")
	}
	for i, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		if key.Status == tinkpb.KeyStatusType_ENABLED || key.Status == tinkpb.KeyStatusType_DISABLED {
			km.ks.Key[i].Status = tinkpb.KeyStatusType_DISABLED
			return nil
		}
		return fmt.Errorf("keyset_manager: cannot disable key with id %d with status %s", keyID, key.Status.String())
	}
	return fmt.Errorf("keyset_manager: key with id %d not found", keyID)
}

// Delete will delete the key with given keyID, removing the key from the keyset entirely
// returns an error if the key is not found or it is the primary key
func (km *Manager) Delete(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset_manager: cannot delete key, no keyset")
	}
	if km.ks.PrimaryKeyId == keyID {
		return errors.New("keyset_manager: cannot delete the primary key")
	}
	deleteIdx, found := 0, false
	for i, key := range km.ks.Key {
		if key.KeyId == keyID {
			found = true
			deleteIdx = i
		}
	}
	if !found {
		return fmt.Errorf("keyset_manager: key with id %d not found", keyID)
	}
	// swap elements
	km.ks.Key[deleteIdx] = km.ks.Key[len(km.ks.Key)-1]
	// trim last element
	km.ks.Key = km.ks.Key[:len(km.ks.Key)-1]
	return nil
}

// Destroy will destroy the key material associated with a given keyID
// returns an error if the key is not found or it is the primary key
func (km *Manager) Destroy(keyID uint32) error {
	if km.ks == nil {
		return errors.New("keyset_manager: cannot destroy key, no keyset")
	}
	if km.ks.PrimaryKeyId == keyID {
		return errors.New("keyset_manager: cannot destroy the primary key")
	}
	for i, key := range km.ks.Key {
		if key.KeyId != keyID {
			continue
		}
		switch key.Status {
		case tinkpb.KeyStatusType_ENABLED, tinkpb.KeyStatusType_DISABLED, tinkpb.KeyStatusType_DESTROYED:
			km.ks.Key[i].Status = tinkpb.KeyStatusType_DESTROYED
			km.ks.Key[i].KeyData = nil
			return nil
		default:
			return fmt.Errorf("keyset_manager: cannot destroy key with id %d with status %s", keyID, km.ks.Key[i].Status.String())
		}
	}
	return fmt.Errorf("keyset_manager: key with id %d not found", keyID)
}

// Handle creates a new Handle for the managed keyset.
func (km *Manager) Handle() (*Handle, error) {
	return &Handle{km.ks}, nil
}

// newKeyID generates a key id that has not been used by any key in the keyset.
func (km *Manager) newKeyID() uint32 {
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
