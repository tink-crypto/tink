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

#ifndef TINK_RESTRICTED_BIG_INTEGER_H_
#define TINK_RESTRICTED_BIG_INTEGER_H_

#include <cstdint>

#include "absl/strings/string_view.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

// Stores a RestrictedBigInteger value as a big endian encoded string, which
// requires secret key access. Removes leading zeros prior to creation.
// This class is particularly useful for working with certain primitives which
// use secret big integers types for the key material.
class RestrictedBigInteger {
 public:
  // Copyable and movable.
  RestrictedBigInteger(const RestrictedBigInteger& other) = default;
  RestrictedBigInteger& operator=(const RestrictedBigInteger& other) = default;
  RestrictedBigInteger(RestrictedBigInteger&& other) = default;
  RestrictedBigInteger& operator=(RestrictedBigInteger&& other) = default;

  // Creates a new RestrictedBigInteger object that wraps `secret_big_integer`,
  // after removing the leading zeros. Note that creating a `token` requires
  // access to InsecureSecretKeyAccess::Get().
  explicit RestrictedBigInteger(absl::string_view secret_big_integer,
                                SecretKeyAccessToken token)
      : secret_(util::SecretDataFromStringView(secret_big_integer.substr(
            secret_big_integer.find_first_not_of('\0')))) {}

  // Returns the value of this RestrictedBigInteger object.
  absl::string_view GetSecret(SecretKeyAccessToken token) const {
    return util::SecretDataAsStringView(secret_);
  }

  int64_t SizeInBytes() const { return secret_.size(); }

  bool operator==(const RestrictedBigInteger& other) const;
  bool operator!=(const RestrictedBigInteger& other) const {
    return !(*this == other);
  }

 private:
  util::SecretData secret_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_RESTRICTED_BIG_INTEGER_H_
