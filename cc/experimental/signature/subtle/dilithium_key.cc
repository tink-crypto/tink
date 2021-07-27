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

#include "tink/experimental/signature/subtle/dilithium_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<DilithiumKey> DilithiumKey::FromSeedsAndMatrix(
    util::SecretData seeds_and_matrix) {
  return DilithiumKey(seeds_and_matrix);
}

const util::SecretData& DilithiumKey::SeedsAndMatrix() const {
  return seeds_and_matrix_;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
