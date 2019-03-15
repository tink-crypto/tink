// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_UTIL_KEYSET_UTIL_H_
#define TINK_UTIL_KEYSET_UTIL_H_

#include "tink/keyset_handle.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// The helpers below are "packed" in a class to allow for an easier
// addition of them as a "friend class".
class TestKeysetHandle {
 public:
  // Creates a KeysetHandle object for the given 'keyset'.
  static std::unique_ptr<KeysetHandle> GetKeysetHandle(
      const google::crypto::tink::Keyset& keyset);

  // Returns a Keyset-proto from the given 'keyset_handle'.
  static const google::crypto::tink::Keyset& GetKeyset(
      const KeysetHandle& keyset_handle);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_KEYSET_UTIL_H_
