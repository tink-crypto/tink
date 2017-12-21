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
	"fmt"
	"github.com/golang/protobuf/proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"sync"
)

// encryptedKeysetHandle provides utilities to create keyset handles from keysets
// that are encrypted with a Master key.
var ekhInstance *encryptedKeysetHandle
var encryptedKeysetHandleOnce sync.Once

type encryptedKeysetHandle struct{}

// EncryptedKeysetHandle returns the single instance of encryptedKeysetHandle.
func EncryptedKeysetHandle() *encryptedKeysetHandle {
	encryptedKeysetHandleOnce.Do(func() {
		ekhInstance = new(encryptedKeysetHandle)
	})
	return ekhInstance
}

var errInvalidEncryptedKeyset = fmt.Errorf("encrypted_keyset_handle: invalid keyset")
var errInvalidMasterKey = fmt.Errorf("encrypted_keyset_handle: invalid master key")

// ParseSerializedKeyset creates a new keyset handle from the given serialized
// EncryptedKeyset. The keyset is encrypted with the given master key.
func (handle *encryptedKeysetHandle) ParseSerializedKeyset(
	serializedEncryptedKeyset []byte, masterKey Aead) (*KeysetHandle, error) {
	if len(serializedEncryptedKeyset) == 0 {
		return nil, errInvalidEncryptedKeyset
	}
	if masterKey == nil {
		return nil, errInvalidMasterKey
	}
	encryptedKeyset := new(tinkpb.EncryptedKeyset)
	if err := proto.Unmarshal(serializedEncryptedKeyset, encryptedKeyset); err != nil {
		return nil, errInvalidEncryptedKeyset
	}
	return handle.ParseKeyset(encryptedKeyset, masterKey)
}

// ParseKeyset creates a new keyset handle from the given EncryptedKeyset and master key.
func (_ *encryptedKeysetHandle) ParseKeyset(
	encryptedKeyset *tinkpb.EncryptedKeyset, masterKey Aead) (*KeysetHandle, error) {
	if encryptedKeyset == nil || len(encryptedKeyset.EncryptedKeyset) == 0 {
		return nil, errInvalidEncryptedKeyset
	}
	if masterKey == nil {
		return nil, errInvalidMasterKey
	}
	keyset, err := DecryptKeyset(encryptedKeyset, masterKey)
	if err != nil {
		return nil, fmt.Errorf("encrypted_keyset_handle: %s", err)
	}
	return newKeysetHandle(keyset, encryptedKeyset)
}

// GenerateNew creates a keyset handle that contains a single fresh key generated
// according to the given key template. The keyset is encrypted with the given master key.
func (_ *encryptedKeysetHandle) GenerateNew(
	template *tinkpb.KeyTemplate, masterKey Aead) (*KeysetHandle, error) {
	if masterKey == nil {
		return nil, errInvalidMasterKey
	}
	keysetManager := NewKeysetManager(template, masterKey, nil)
	if err := keysetManager.Rotate(); err != nil {
		return nil, fmt.Errorf("encrypted_keyset_handle: %s", err)
	}
	handle, err := keysetManager.GetKeysetHandle()
	if err != nil {
		return nil, fmt.Errorf("encrypted_keyset_handle: %s", err)
	}
	return handle, nil
}
