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
  "github.com/google/tink/go/subtle/random"
  "github.com/google/tink/go/util/util"
  proto "github.com/golang/protobuf/proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// KeysetManager manages a Keyset-proto, with convenience methods that rotate,
// disable, enable or destroy keys.
// Note: It is not thread-safe.
type KeysetManager struct {
  keyTemplate *tinkpb.KeyTemplate
  outputPrefixType tinkpb.OutputPrefixType
  masterKey Aead
  keyset *tinkpb.Keyset
}

// NewKeysetManager creates a new instance of keyset manager.
func NewKeysetManager(keyTemplate *tinkpb.KeyTemplate,
                      outputPrefixType tinkpb.OutputPrefixType,
                      masterKey Aead,
                      keyset *tinkpb.Keyset) *KeysetManager {
  ret := new(KeysetManager)
  ret.SetKeyTemplate(keyTemplate)
  ret.SetOutputPrefixType(outputPrefixType)
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
  key := util.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, km.outputPrefixType)
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
  serializedKeyset, err := proto.Marshal(km.keyset)
  if err != nil {
    return nil, fmt.Errorf("keyset_manager: cannot serialize keyset: %s", err)
  }
  ad := []byte{}
  serializedEncryptedKeyset, err := km.masterKey.Encrypt(serializedKeyset, ad)
  // check if we can decrypt, to detect errors
  decrypted, err := km.masterKey.Decrypt(serializedEncryptedKeyset, ad)
  if err != nil || !bytes.Equal(decrypted, serializedKeyset) {
    return nil, fmt.Errorf("keyset_manager: cannot encrypt keyset: %s", err)
  }
  info, err := util.GetKeysetInfo(km.keyset)
  if err != nil {
    return nil, fmt.Errorf("keyset_manager: cannot get keyset info: %s", err)
  }
  encryptedKeyset := util.NewEncryptedKeyset(serializedEncryptedKeyset, info)
  return newKeysetHandle(km.keyset, encryptedKeyset)
}

// SetKeyTemplate sets the key template of the manager.
func (km *KeysetManager) SetKeyTemplate(template *tinkpb.KeyTemplate) {
  km.keyTemplate = template
}


// SetOutputPrefixType sets the output prefix type of the manager.
func (km *KeysetManager) SetOutputPrefixType(outputPrefixType tinkpb.OutputPrefixType) {
  km.outputPrefixType = outputPrefixType
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

// OutputPrefixType returns the output prefix type of the manager.
func (km *KeysetManager) OutputPrefixType() tinkpb.OutputPrefixType {
  return km.outputPrefixType
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