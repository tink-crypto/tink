// Copyright 2017 Google Inc.
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

package tink

import (
	"bytes"
	"fmt"
	proto "github.com/golang/protobuf/proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/util/util"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// emptyAad is the additional authenticated data that is used in the encryption
// and decryption of keysets
var emptyAad = []byte{}

// KeysetManager manages a Keyset-proto, with convenience methods that rotate,
// disable, enable or destroy keys.
// Note: It is not thread-safe.
type KeysetManager struct {
	keyTemplate *tinkpb.KeyTemplate
	masterKey   Aead
	keyset      *tinkpb.Keyset
}

// NewKeysetManager creates a new instance of keyset manager.
func NewKeysetManager(keyTemplate *tinkpb.KeyTemplate,
	masterKey Aead,
	keyset *tinkpb.Keyset) *KeysetManager {
	ret := new(KeysetManager)
	ret.SetKeyTemplate(keyTemplate)
	ret.SetMasterKey(masterKey)
	ret.SetKeyset(keyset)
	return ret
}

// Rotate generates a fresh key using the key template of the current keyset manager
// and sets the new key as the primary key.
func (km *KeysetManager) Rotate() error {
	return km.RotateWithTemplate(km.keyTemplate)
}

// RotateWithTemplate generates a fresh key using the given key template and
// sets the new key as the primary key.
func (km *KeysetManager) RotateWithTemplate(keyTemplate *tinkpb.KeyTemplate) error {
	if keyTemplate == nil {
		return fmt.Errorf("keyset_manager: cannot rotate, need key template")
	}
	keyData, err := Registry().NewKeyData(keyTemplate)
	if err != nil {
		return fmt.Errorf("keyset_manager: cannot create KeyData: %s", err)
	}
	keyID := km.newKeyID()
	outputPrefixType := keyTemplate.OutputPrefixType
	if outputPrefixType == tinkpb.OutputPrefixType_UNKNOWN_PREFIX {
		outputPrefixType = tinkpb.OutputPrefixType_TINK
	}
	key := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefixType)
	// Set the new key as the primary key
	km.keyset.Key = append(km.keyset.Key, key)
	km.keyset.PrimaryKeyId = keyID
	return nil
}

// GetKeysetHandle creates a new KeysetHandle for the managed keyset.
func (km *KeysetManager) GetKeysetHandle() (*KeysetHandle, error) {
	if km.masterKey == nil {
		return newKeysetHandle(km.keyset, nil)
	}
	encryptedKeyset, err := EncryptKeyset(km.keyset, km.masterKey)
	if err != nil {
		return nil, err
	}
	return newKeysetHandle(km.keyset, encryptedKeyset)
}

// SetKeyTemplate sets the key template of the manager.
func (km *KeysetManager) SetKeyTemplate(template *tinkpb.KeyTemplate) {
	km.keyTemplate = template
}

// SetMasterKey sets the master key of the manager.
func (km *KeysetManager) SetMasterKey(masterKey Aead) {
	km.masterKey = masterKey
}

// SetKeyset sets the keyset of the manager. If the input is nil, it will use
// an empty keyset as the input instead.
func (km *KeysetManager) SetKeyset(keyset *tinkpb.Keyset) {
	if keyset == nil {
		km.keyset = new(tinkpb.Keyset)
	} else {
		km.keyset = keyset
	}
}

// KeyTemplate returns the key template of the manager.
func (km *KeysetManager) KeyTemplate() *tinkpb.KeyTemplate {
	return km.keyTemplate
}

// MasterKey returns the master key of the manager.
func (km *KeysetManager) MasterKey() Aead {
	return km.masterKey
}

// Keyset returns the keyset of the manager.
func (km *KeysetManager) Keyset() *tinkpb.Keyset {
	return km.keyset
}

// newKeyID generates a key id that has not been used by any key in the keyset.
func (km *KeysetManager) newKeyID() uint32 {
	for {
		ret := random.GetRandomUint32()
		ok := true
		for _, key := range km.keyset.Key {
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

// EncryptKeyset encrypts the given keyset using the given master key.
func EncryptKeyset(keyset *tinkpb.Keyset,
	masterKey Aead) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, fmt.Errorf("keyset_manager: invalid keyset")
	}
	encrypted, err := masterKey.Encrypt(serializedKeyset, emptyAad)
	if err != nil {
		return nil, fmt.Errorf("keyset_manager: encrypted failed: %s", err)
	}
	// check if we can decrypt, to detect errors
	decrypted, err := masterKey.Decrypt(encrypted, emptyAad)
	if err != nil || !bytes.Equal(decrypted, serializedKeyset) {
		return nil, fmt.Errorf("keyset_manager: encryption failed: %s", err)
	}
	// get keyset info
	info, err := util.GetKeysetInfo(keyset)
	if err != nil {
		return nil, fmt.Errorf("keyset_manager: cannot get keyset info: %s", err)
	}
	encryptedKeyset := util.NewEncryptedKeyset(encrypted, info)
	return encryptedKeyset, nil
}

// DecryptKeyset decrypts the given keyset using the given master key
func DecryptKeyset(encryptedKeyset *tinkpb.EncryptedKeyset,
	masterKey Aead) (*tinkpb.Keyset, error) {
	decrypted, err := masterKey.Decrypt(encryptedKeyset.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("keyset_manager: decryption failed: %s", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, fmt.Errorf("keyset_manager: invalid encrypted keyset")
	}
	return keyset, nil
}
