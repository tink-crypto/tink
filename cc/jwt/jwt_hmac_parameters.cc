// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_hmac_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<JwtHmacParameters> JwtHmacParameters::Create(
    int key_size_in_bytes, KidStrategy kid_strategy, Algorithm algorithm) {
  if (key_size_in_bytes < 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key size should be at least 16 bytes, got ",
                     key_size_in_bytes, " bytes."));
  }
  static const std::set<KidStrategy>* kSupportedKidStrategies =
      new std::set<KidStrategy>({KidStrategy::kBase64EncodedKeyId,
                                 KidStrategy::kIgnored, KidStrategy::kCustom});
  if (kSupportedKidStrategies->find(kid_strategy) ==
      kSupportedKidStrategies->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create JWT HMAC parameters with unknown kid strategy.");
  }
  static const std::set<Algorithm>* kSupportedAlgorithms =
      new std::set<Algorithm>(
          {Algorithm::kHs256, Algorithm::kHs384, Algorithm::kHs512});
  if (kSupportedAlgorithms->find(algorithm) == kSupportedAlgorithms->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create JWT HMAC parameters with unknown algorithm.");
  }
  return JwtHmacParameters(key_size_in_bytes, kid_strategy, algorithm);
}

bool JwtHmacParameters::operator==(const Parameters& other) const {
  const JwtHmacParameters* that =
      dynamic_cast<const JwtHmacParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_size_in_bytes_ != that->key_size_in_bytes_) {
    return false;
  }
  if (kid_strategy_ != that->kid_strategy_) {
    return false;
  }
  if (algorithm_ != that->algorithm_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
