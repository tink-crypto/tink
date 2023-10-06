// Copyright 2023 Google LLC
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

#include "tink/restricted_big_integer.h"

#include "openssl/crypto.h"

namespace crypto {
namespace tink {

bool RestrictedBigInteger::operator==(const RestrictedBigInteger& other) const {
  if (secret_.size() != other.secret_.size()) {
    return false;
  }

  return CRYPTO_memcmp(secret_.data(), other.secret_.data(), secret_.size()) ==
         0;
}

}  // namespace tink
}  // namespace crypto
