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
package util

import (
  "errors"
  "fmt"
  "hash"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  commonpb "github.com/google/tink/proto/common_go_proto"
)

/**
 * Checks whether the given version is valid. The version is valid only if
 * it is the range [0..{@code maxExpected}]
 */
func ValidateVersion(version uint32, maxExpected uint32) error {
  if version > maxExpected {
    msg := fmt.Sprintf("key has version %v; " +
        "only keys with version in range [0..%v] are supported",
        version, maxExpected)
    return errors.New("subtle/util: " + msg)
  }
  return nil
}

/**
 * @return the corresponding hash function of {@code hashType}
 */
func GetHashFunc(hashType commonpb.HashType) func() hash.Hash {
  switch hashType {
    case commonpb.HashType_SHA1:
      return sha1.New
    case commonpb.HashType_SHA256:
      return sha256.New
    case commonpb.HashType_SHA512:
      return sha512.New
    default:
      return nil
  }
}