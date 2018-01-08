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

package mac

import (
  . "github.com/google/tink/proto/common_proto"
  . "github.com/google/tink/proto/hmac_proto"
)

// Utilities for Hmac Protos
func NewHmacParams(hashType HashType, tagSize uint32) *HmacParams {
  return &HmacParams{
    Hash:    hashType,
    TagSize: tagSize,
  }
}

func NewHmacKey(params *HmacParams, version uint32, keyValue []byte) *HmacKey {
  return &HmacKey{
    Version:  version,
    Params:   params,
    KeyValue: keyValue,
  }
}

func NewHmacKeyFormat(params *HmacParams, keySize uint32) *HmacKeyFormat {
  return &HmacKeyFormat{
    Params:  params,
    KeySize: keySize,
  }
}
