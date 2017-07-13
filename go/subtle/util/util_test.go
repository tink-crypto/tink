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
package util_test

import (
  "testing"
  "github.com/google/tink/go/subtle/util"
  commonpb "github.com/google/tink/proto/common_go_proto"
)

func TestValidateVersion(t *testing.T) {
  if util.ValidateVersion(2, 1) == nil ||
      util.ValidateVersion(1, 1) != nil ||
      util.ValidateVersion(1, 2) != nil {
    t.Errorf("incorrect version validation")
  }
}

func TestGetHashFunc(t *testing.T) {
  if util.GetHashFunc(commonpb.HashType_SHA1) == nil ||
      util.GetHashFunc(commonpb.HashType_SHA256) == nil ||
      util.GetHashFunc(commonpb.HashType_SHA512) == nil {
    t.Errorf("expect a hash function for valid hash types")
  }
  if util.GetHashFunc(commonpb.HashType_UNKNOWN_HASH) != nil {
    t.Errorf("unexpected result for invalid hash types")
  }
}

func TestValidateAesKeySize(t *testing.T) {
  keySizes := []uint32{16, 24, 32}
  for _, size := range keySizes {
    if err := util.ValidateAesKeySize(size); err != nil {
      t.Errorf("unexpected error when key size is valid")
    }
    if err := util.ValidateAesKeySize(size+1); err == nil {
      t.Errorf("expect an error when key size is invalid")
    }
  }
}
