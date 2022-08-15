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

#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using google::crypto::tink::OutputPrefixType;

namespace {

class JwtPublicKeySignSetWrapper : public JwtPublicKeySign {
 public:
  explicit JwtPublicKeySignSetWrapper(
      std::unique_ptr<PrimitiveSet<JwtPublicKeySignInternal>> jwt_sign_set)
      : jwt_sign_set_(std::move(jwt_sign_set)) {}

  crypto::tink::util::StatusOr<std::string> SignAndEncode(
      const crypto::tink::RawJwt& token) const override;

  ~JwtPublicKeySignSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<JwtPublicKeySignInternal>> jwt_sign_set_;
};

util::Status Validate(PrimitiveSet<JwtPublicKeySignInternal>* jwt_sign_set) {
  if (jwt_sign_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "jwt_sign_set must be non-NULL");
  }
  if (jwt_sign_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "jwt_sign_set has no primary");
  }
  for (const auto* entry : jwt_sign_set->get_all()) {
    if ((entry->get_output_prefix_type() != OutputPrefixType::RAW) &&
        (entry->get_output_prefix_type() != OutputPrefixType::TINK)) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "all JWT keys must be either RAW or TINK");
    }
  }
  return util::OkStatus();
}

util::StatusOr<std::string> JwtPublicKeySignSetWrapper::SignAndEncode(
    const crypto::tink::RawJwt& token) const {
  auto primary = jwt_sign_set_->get_primary();
  return primary->get_primitive().SignAndEncodeWithKid(
      token, GetKid(primary->get_key_id(), primary->get_output_prefix_type()));
}

}  // namespace

util::StatusOr<std::unique_ptr<JwtPublicKeySign>> JwtPublicKeySignWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<JwtPublicKeySignInternal>> jwt_sign_set)
    const {
  util::Status status = Validate(jwt_sign_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<JwtPublicKeySign> jwt_sign =
      absl::make_unique<JwtPublicKeySignSetWrapper>(std::move(jwt_sign_set));
  return std::move(jwt_sign);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
