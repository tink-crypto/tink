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
package tink_test

import (
  "testing"
  "github.com/google/tink/go/tink/tink"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

var tests = []struct{
  keyId uint32
  result string // expected prefix
}{
  {
    keyId: 1000000,
    result: string([]byte{0, 15, 66, 64}),
  },
  {
    keyId: 4294967295,
    result: string([]byte{255, 255, 255, 255}),
  },
  {
    keyId: 0,
    result: string([]byte{0, 0, 0, 0}),
  },
}

func TestGetOutputPrefix(t *testing.T) {
  key := new(tinkpb.Keyset_Key)
  for i, test := range tests {
    key.KeyId = test.keyId
    // legacy type
    key.OutputPrefixType = tinkpb.OutputPrefixType_LEGACY
    prefix, err := tink.GetOutputPrefix(key)
    if err != nil || !validatePrefix(prefix, tink.LEGACY_START_BYTE, test.result){
      t.Errorf("incorrect legacy prefix in test %d", i)
    }
    // crunchy type
    key.OutputPrefixType = tinkpb.OutputPrefixType_CRUNCHY
    prefix, err = tink.GetOutputPrefix(key)
    if err != nil || !validatePrefix(prefix, tink.LEGACY_START_BYTE, test.result){
      t.Errorf("incorrect legacy prefix in test %d", i)
    }
    // tink type
    key.OutputPrefixType = tinkpb.OutputPrefixType_TINK
    prefix, err = tink.GetOutputPrefix(key)
    if err != nil || !validatePrefix(prefix, tink.TINK_START_BYTE, test.result){
      t.Errorf("incorrect tink prefix in test %d", i)
    }
    // raw type
    key.OutputPrefixType = tinkpb.OutputPrefixType_RAW
    prefix, err = tink.GetOutputPrefix(key)
    if err != nil || prefix != tink.RAW_PREFIX {
      t.Errorf("incorrect raw prefix in test %d", i)
    }
  }
  // unknown prefix type
  key.OutputPrefixType = tinkpb.OutputPrefixType_UNKNOWN_PREFIX
  if _, err := tink.GetOutputPrefix(key); err == nil {
    t.Errorf("expect an error when prefix type is unknown")
  }
}

func validatePrefix(prefix string, startByte byte, key string) bool {
  if prefix[0] != startByte {
    return false
  }
  return prefix[1:] == key
}