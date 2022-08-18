// Copyright 2022 Google LLC
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

#include "tink/restricted_data.h"

#include <iostream>

#include "openssl/crypto.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

RestrictedData::RestrictedData(int64_t num_random_bytes) {
  // TODO(b/243001146): Replace following crash with Tink library call.
  if (num_random_bytes < 0) {
    std::cerr << "Cannot generate a negative number of random bytes.\n";
    std::abort();
  }
  secret_ = util::SecretDataFromStringView(
      subtle::Random::GetRandomBytes(num_random_bytes));
}

bool RestrictedData::operator==(const RestrictedData& other) const {
  if (secret_.size() != other.secret_.size()) {
    return false;
  }
  return CRYPTO_memcmp(secret_.data(), other.secret_.data(), secret_.size()) ==
         0;
}

}  // namespace tink
}  // namespace crypto
