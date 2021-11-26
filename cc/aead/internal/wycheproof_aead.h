// Copyright 2021 Google LLC
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
#ifndef TINK_AEAD_INTERNAL_WYCHEPROOF_AEAD_H_
#define TINK_AEAD_INTERNAL_WYCHEPROOF_AEAD_H_

#include <string>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Struct representing a Wycheproof test vector.
struct WycheproofTestVector {
  std::string comment;
  std::string key;
  std::string nonce;
  std::string msg;
  std::string ct;
  std::string aad;
  std::string tag;
  std::string id;
  std::string expected;
};

// Read test vectors from the Wycheproof project that are rooted at `root`.
// Filter out instances with unsupported key sizes, iv size or tag size.
std::vector<WycheproofTestVector> ReadWycheproofTestVectors(
    absl::string_view file_name, int allowed_tag_size_in_bytes,
    int allowed_iv_size_in_bytes,
    absl::flat_hash_set<int> allowed_key_sizes_in_bits);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_WYCHEPROOF_AEAD_H_
