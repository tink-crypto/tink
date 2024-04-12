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

#include "tink/jwt/jwt_hmac_key.h"

#include <string>

#include "absl/base/internal/endian.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

JwtHmacKey::Builder& JwtHmacKey::Builder::SetParameters(
    const JwtHmacParameters& parameters) {
  parameters_ = parameters;
  return *this;
}

JwtHmacKey::Builder& JwtHmacKey::Builder::SetKeyBytes(
    const RestrictedData& key_bytes) {
  key_bytes_ = key_bytes;
  return *this;
}

JwtHmacKey::Builder& JwtHmacKey::Builder::SetIdRequirement(int id_requirement) {
  id_requirement_ = id_requirement;
  return *this;
}

JwtHmacKey::Builder& JwtHmacKey::Builder::SetCustomKid(
    absl::string_view custom_kid) {
  custom_kid_ = custom_kid.data();
  return *this;
}

util::StatusOr<absl::optional<std::string>> JwtHmacKey::Builder::ComputeKid() {
  switch (parameters_->GetKidStrategy()) {
    case JwtHmacParameters::KidStrategy::kBase64EncodedKeyId: {
      if (custom_kid_.has_value()) {
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            "Custom kid must not be set for KidStrategy::kBase64EncodedKeyId.");
      }
      std::string base64_kid;
      char buffer[4];
      absl::big_endian::Store32(buffer, *id_requirement_);
      absl::WebSafeBase64Escape(absl::string_view(buffer, 4), &base64_kid);
      return base64_kid;
    }
    case JwtHmacParameters::KidStrategy::kCustom: {
      if (!custom_kid_.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "Custom kid must be set for KidStrategy::kCustom.");
      }
      return custom_kid_;
    }
    case JwtHmacParameters::KidStrategy::kIgnored: {
      if (custom_kid_.has_value()) {
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            "Custom kid must not be set for KidStrategy::kIgnored.");
      }
      return absl::nullopt;
    }
    default:
      // Should be unreachable if all valid kid strategies have been handled.
      return util::Status(absl::StatusCode::kFailedPrecondition,
                          "Unknown kid strategy.");
  }
}

util::StatusOr<JwtHmacKey> JwtHmacKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "JWT HMAC parameters must be specified.");
  }
  if (!key_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "JWT HMAC key bytes must be specified.");
  }
  if (parameters_->KeySizeInBytes() != key_bytes_->size()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Actual JWT HMAC key size does not match size specified in "
        "the parameters.");
  }
  if (parameters_->HasIdRequirement() && !id_requirement_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters_->HasIdRequirement() && id_requirement_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  util::StatusOr<absl::optional<std::string>> kid = ComputeKid();
  if (!kid.ok()) {
    return kid.status();
  }
  return JwtHmacKey(*parameters_, *key_bytes_, id_requirement_, *kid);
}

bool JwtHmacKey::operator==(const Key& other) const {
  const JwtHmacKey* that = dynamic_cast<const JwtHmacKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (parameters_ != that->parameters_) {
    return false;
  }
  if (key_bytes_ != that->key_bytes_) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  if (kid_ != that->kid_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
