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

#ifndef TINK_JWT_JWT_HMAC_KEY_H_
#define TINK_JWT_JWT_HMAC_KEY_H_

#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_mac_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents functions to authenticate and verify JWTs using HMAC.
class JwtHmacKey : public JwtMacKey {
 public:
  // Creates JWT HMAC key instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetParameters(const JwtHmacParameters& parameters);
    Builder& SetKeyBytes(const RestrictedData& key_bytes);
    Builder& SetIdRequirement(int id_requirement);
    Builder& SetCustomKid(absl::string_view custom_kid);

    // Creates JWT HMAC key object from this builder.
    util::StatusOr<JwtHmacKey> Build(PartialKeyAccessToken token);

   private:
    util::StatusOr<absl::optional<std::string>> ComputeKid();

    absl::optional<JwtHmacParameters> parameters_;
    absl::optional<RestrictedData> key_bytes_;
    absl::optional<int> id_requirement_;
    absl::optional<std::string> custom_kid_;
  };

  // Copyable and movable.
  JwtHmacKey(const JwtHmacKey& other) = default;
  JwtHmacKey& operator=(const JwtHmacKey& other) = default;
  JwtHmacKey(JwtHmacKey&& other) = default;
  JwtHmacKey& operator=(JwtHmacKey&& other) = default;

  const RestrictedData& GetKeyBytes(PartialKeyAccessToken token) const {
    return key_bytes_;
  }

  const JwtHmacParameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  absl::optional<std::string> GetKid() const override { return kid_; }

  bool operator==(const Key& other) const override;

 private:
  JwtHmacKey(const JwtHmacParameters& parameters,
             const RestrictedData& key_bytes,
             absl::optional<int> id_requirement,
             absl::optional<std::string> kid)
      : parameters_(parameters),
        key_bytes_(key_bytes),
        id_requirement_(id_requirement),
        kid_(kid) {}

  JwtHmacParameters parameters_;
  RestrictedData key_bytes_;
  absl::optional<int> id_requirement_;
  absl::optional<std::string> kid_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_HMAC_KEY_H_
