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

#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"

#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using google::crypto::tink::OutputPrefixType;

namespace {

class JwtPublicKeyVerifySetWrapper : public JwtPublicKeyVerify {
 public:
  explicit JwtPublicKeyVerifySetWrapper(
      std::unique_ptr<PrimitiveSet<JwtPublicKeyVerify>> jwt_verify_set)
      : jwt_verify_set_(std::move(jwt_verify_set)) {}

  crypto::tink::util::StatusOr<crypto::tink::VerifiedJwt> VerifyAndDecode(
      absl::string_view compact,
      const crypto::tink::JwtValidator& validator) const override;

  ~JwtPublicKeyVerifySetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<JwtPublicKeyVerify>> jwt_verify_set_;
};

util::Status Validate(PrimitiveSet<JwtPublicKeyVerify>* jwt_verify_set) {
  if (jwt_verify_set == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "jwt_verify_set must be non-NULL");
  }
  for (const auto* entry : jwt_verify_set->get_all()) {
    if ((entry->get_output_prefix_type() != OutputPrefixType::RAW) &&
        (entry->get_output_prefix_type() != OutputPrefixType::TINK)) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "all JWT keys must be either RAW or TINK");
    }
  }
  return util::Status::OK;
}

util::StatusOr<crypto::tink::VerifiedJwt>
JwtPublicKeyVerifySetWrapper::VerifyAndDecode(
    absl::string_view compact,
    const crypto::tink::JwtValidator& validator) const {
  absl::optional<util::Status> interesting_status;
  for (const auto* entry : jwt_verify_set_->get_all()) {
    JwtPublicKeyVerify& jwt_verify = entry->get_primitive();
    auto verified_jwt_or = jwt_verify.VerifyAndDecode(compact, validator);
    if (verified_jwt_or.ok()) {
      return verified_jwt_or;
    } else if (verified_jwt_or.status().error_code() !=
               util::error::UNAUTHENTICATED) {
      // errors that are not the result of a signature verification
      interesting_status = verified_jwt_or.status();
    }
  }
  if (interesting_status.has_value()) {
    return *std::move(interesting_status);
  }
  return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
}

}  // namespace

util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>>
JwtPublicKeyVerifyWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<JwtPublicKeyVerify>> jwt_verify_set) const {
  util::Status status = Validate(jwt_verify_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<JwtPublicKeyVerify> jwt_verify =
      absl::make_unique<JwtPublicKeyVerifySetWrapper>(
          std::move(jwt_verify_set));
  return std::move(jwt_verify);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
