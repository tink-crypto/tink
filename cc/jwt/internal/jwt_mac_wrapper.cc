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

#include "tink/jwt/internal/jwt_mac_wrapper.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::google::crypto::tink::OutputPrefixType;

namespace {

class JwtMacSetWrapper : public JwtMac {
 public:
  explicit JwtMacSetWrapper(
      std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set)
      : jwt_mac_set_(std::move(jwt_mac_set)) {}

  crypto::tink::util::StatusOr<std::string> ComputeMacAndEncode(
      const crypto::tink::RawJwt& token) const override;

  crypto::tink::util::StatusOr<crypto::tink::VerifiedJwt> VerifyMacAndDecode(
      absl::string_view compact,
      const crypto::tink::JwtValidator& validator) const override;

  ~JwtMacSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set_;
};

util::Status Validate(PrimitiveSet<JwtMacInternal>* jwt_mac_set) {
  if (jwt_mac_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "jwt_mac_set must be non-NULL");
  }
  if (jwt_mac_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "jwt_mac_set has no primary");
  }
  for (const auto* entry : jwt_mac_set->get_all()) {
    if ((entry->get_output_prefix_type() != OutputPrefixType::RAW) &&
        (entry->get_output_prefix_type() != OutputPrefixType::TINK)) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "all JWT keys must be either RAW or TINK");
    }
  }
  return util::OkStatus();
}

util::StatusOr<std::string> JwtMacSetWrapper::ComputeMacAndEncode(
    const crypto::tink::RawJwt& token) const {
  auto primary = jwt_mac_set_->get_primary();
  absl::optional<std::string> kid =
      GetKid(primary->get_key_id(), primary->get_output_prefix_type());
  return primary->get_primitive().ComputeMacAndEncodeWithKid(token, kid);
}

util::StatusOr<crypto::tink::VerifiedJwt> JwtMacSetWrapper::VerifyMacAndDecode(
    absl::string_view compact,
    const crypto::tink::JwtValidator& validator) const {
  absl::optional<util::Status> interesting_status;
  for (const auto* mac_entry : jwt_mac_set_->get_all()) {
    JwtMacInternal& jwt_mac = mac_entry->get_primitive();
    absl::optional<std::string> kid =
        GetKid(mac_entry->get_key_id(), mac_entry->get_output_prefix_type());
    util::StatusOr<VerifiedJwt> verified_jwt =
        jwt_mac.VerifyMacAndDecodeWithKid(compact, validator, kid);
    if (verified_jwt.ok()) {
      return verified_jwt;
    } else if (verified_jwt.status().code() !=
               absl::StatusCode::kUnauthenticated) {
      // errors that are not the result of a MAC verification
      interesting_status = verified_jwt.status();
    }
  }
  if (interesting_status.has_value()) {
    return *interesting_status;
  }
  return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
}

}  // namespace

util::StatusOr<std::unique_ptr<JwtMac>> JwtMacWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set) const {
  util::Status status = Validate(jwt_mac_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<JwtMac> jwt_mac =
      absl::make_unique<JwtMacSetWrapper>(std::move(jwt_mac_set));
  return std::move(jwt_mac);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
