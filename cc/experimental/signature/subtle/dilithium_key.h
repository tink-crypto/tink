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

#ifndef TINK_EXPERIMENTAL_SIGNATURE_SUBTLE_DILITHIUM_KEY_H_
#define TINK_EXPERIMENTAL_SIGNATURE_SUBTLE_DILITHIUM_KEY_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class DilithiumKey {
 public:
  DilithiumKey(const DilithiumKey& other) = default;
  DilithiumKey& operator=(const DilithiumKey& other) = default;

  static util::StatusOr<DilithiumKey> FromSeedsAndMatrix(
      util::SecretData seeds_and_matrix);

  const util::SecretData& SeedsAndMatrix() const;

 private:
  explicit DilithiumKey(util::SecretData seeds_and_matrix)
      : seeds_and_matrix_(std::move(seeds_and_matrix)) {}

  const util::SecretData seeds_and_matrix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_SIGNATURE_SUBTLE_DILITHIUM_KEY_H_
