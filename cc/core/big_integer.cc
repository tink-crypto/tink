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

#include "tink/big_integer.h"

#include <string>

#include "absl/strings/string_view.h"
#include "openssl/crypto.h"

namespace crypto {
namespace tink {

BigInteger::BigInteger(absl::string_view big_integer) {
  int padding_pos = big_integer.find_first_not_of('\0');
  if (padding_pos != std::string::npos) {
    value_ = std::string(big_integer.substr(padding_pos));
  } else {
    value_ = "";
  }
}

bool BigInteger::operator==(const BigInteger& other) const {
  if (value_.size() != other.value_.size()) {
    return false;
  }

  return CRYPTO_memcmp(value_.data(), other.value_.data(), value_.size()) == 0;
}

}  // namespace tink
}  // namespace crypto
