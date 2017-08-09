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
  "sync"
  "github.com/golang/protobuf/proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// cleartextKeysetHandle provides utilities to creates keyset handles from
// cleartext keysets. This API allows loading cleartext keysets, thus its usage
// should be restricted.
var ckhInstance *cleartextKeysetHandle
var cleartextKeysetHandleOnce sync.Once
type cleartextKeysetHandle struct {}

// CleartextKeysetHandle returns the single instance of cleartextKeysetHandle.
func CleartextKeysetHandle() *cleartextKeysetHandle {
  cleartextKeysetHandleOnce.Do(func() {
    ckhInstance = new(cleartextKeysetHandle)
  })
  return ckhInstance
}

var errInvalidKeyset = fmt.Errorf("cleartext_keyset_handle: invalid keyset")

// ParseSerializedKeyset creates a new keyset handle from the given serialized keyset.
func (_ *cleartextKeysetHandle) ParseSerializedKeyset(serialized []byte) (*KeysetHandle, error) {
  if len(serialized) == 0 {
    return nil, errInvalidKeyset
  }
  keyset := new(tinkpb.Keyset)
  if err := proto.Unmarshal(serialized, keyset); err != nil {
    return nil, errInvalidKeyset
  }
  return newKeysetHandle(keyset, nil)
}

// ParseKeyset creates a new keyset handle from the given keyset.
func (_ *cleartextKeysetHandle) ParseKeyset(keyset *tinkpb.Keyset) (*KeysetHandle, error) {
  return newKeysetHandle(keyset, nil)
}

// GenerateNew creates a keyset handle that contains a single fresh key generated
// according to the given key template.
func (_ *cleartextKeysetHandle) GenerateNew(template *tinkpb.KeyTemplate) (*KeysetHandle, error) {
  manager := NewKeysetManager(template, nil, nil)
  err := manager.Rotate()
  if err != nil {
    return nil, fmt.Errorf("cleartext_keyset_handle: cannot rotate keyset manager: %s", err)
  }
  handle, err := manager.GetKeysetHandle()
  if err != nil {
    return nil, fmt.Errorf("cleartext_keyset_handle: cannot get keyset handle: %s", err)
  }
  return handle, nil
}