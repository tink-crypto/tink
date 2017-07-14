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
package testutil

import (
  . "github.com/google/tink/proto/tink_go_proto"
)

// DummyMac is a dummy implementation of Mac interface.
type DummyMac struct {
  Name string
}

func (h *DummyMac) ComputeMac(data []byte) ([]byte, error) {
  var m []byte
  m = append(m, data...)
  m = append(m, h.Name...)
  return m, nil
}

func (h *DummyMac) VerifyMac(mac []byte, data []byte) (bool, error) {
  return true, nil
}

func NewDummyKey(keyId int, status KeyStatusType, outputPrefixType OutputPrefixType) *Keyset_Key {
  return &Keyset_Key{
    KeyData: new(KeyData),
    Status: status,
    KeyId: uint32(keyId),
    OutputPrefixType: outputPrefixType,
  }
}