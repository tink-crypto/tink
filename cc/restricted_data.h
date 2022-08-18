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

#ifndef TINK_RESTRICTED_DATA_H_
#define TINK_RESTRICTED_DATA_H_

#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

// Stores secret (sensitive) data that is safely destroyed in the event of
// core dumps (similar to `util::SecretData`) and access restricted via
// `SecurityKeyAccessToken`.  This class is particularly useful for
// encapsulating cryptographic key material.
//
// Example:
//     RestrictedData restricted_data(/*num_random_bytes=*/32);
//     const std::string raw_secret =
//         restricted_data.GetSecret(InsecureSecretKeyAccess::Get()).data();
class RestrictedData {
 public:
  // Copyable and movable.
  RestrictedData(const RestrictedData& other) = default;
  RestrictedData& operator=(const RestrictedData& other) = default;
  RestrictedData(RestrictedData&& other) = default;
  RestrictedData& operator=(RestrictedData&& other) = default;

  // Creates a new RestrictedData object that wraps `secret`. Note that creating
  // a `token` requires access to `InsecureSecretKeyAccess::Get()`.
  explicit RestrictedData(absl::string_view secret, SecretKeyAccessToken token)
      : secret_(util::SecretDataFromStringView(secret)) {}

  // Creates a new RestrictedData object that wraps a secret containing
  // `num_random_bytes`. The program will terminate if `num_random_bytes` is a
  // negative value.
  explicit RestrictedData(int64_t num_random_bytes);

  // Returns the secret for this RestrictedData object. Note that creating a
  // `token` requires access to `InsecureSecretKeyAccess::Get()`.
  absl::string_view GetSecret(SecretKeyAccessToken token) const {
    return util::SecretDataAsStringView(secret_);
  }

  int64_t size() const { return secret_.size(); }

  // Constant-time comparison operators.
  bool operator==(const RestrictedData& other) const;
  bool operator!=(const RestrictedData& other) const {
    return !(*this == other);
  }

 private:
  util::SecretData secret_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_RESTRICTED_DATA_H_
