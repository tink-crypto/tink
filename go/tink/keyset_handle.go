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
  "github.com/google/tink/go/util/util"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// KeysetHandle provides abstracted access to Keysets, to limit the exposure
// of actual protocol buffers that hold sensitive key material.
type KeysetHandle struct {
  keyset *tinkpb.Keyset
  encryptedKeyset *tinkpb.EncryptedKeyset
}

// NewKeysetHandle creates a new instance of KeysetHandle using the given keyset
// and encrypted keyset. The given keyset must not be nil. Otherwise, an error will
// be returned.
func newKeysetHandle(keyset *tinkpb.Keyset,
                    encryptedKeyset *tinkpb.EncryptedKeyset) (*KeysetHandle, error) {
  if keyset == nil {
    return nil, fmt.Errorf("key_set_handle: keyset must not be nil")
  }
  return &KeysetHandle{
    keyset: keyset,
    encryptedKeyset: encryptedKeyset,
  }, nil
}

// Keyset returns the keyset component of the keyset handle.
func (h *KeysetHandle) Keyset() *tinkpb.Keyset {
  return h.keyset
}

// EncryptedKeyset returns the encrypted keyset component of the keyset handle.
func (h *KeysetHandle) EncryptedKeyset() *tinkpb.EncryptedKeyset {
  return h.encryptedKeyset
}

// KeysetInfo returns a KeysetInfo object that doesn't contain actual key material.
func (h *KeysetHandle) KeysetInfo() (*tinkpb.KeysetInfo, error) {
  return util.GetKeysetInfo(h.keyset);
}

// String returns the string representation of the KeysetInfo.
func (h *KeysetHandle) String() string {
  info, err := h.KeysetInfo()
  if err != nil {
    return ""
  }
  return info.String()
}