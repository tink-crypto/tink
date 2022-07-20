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

#ifndef TINK_JWT_INTERNAL_JWT_MAC_IMPL_H_
#define TINK_JWT_INTERNAL_JWT_MAC_IMPL_H_

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/mac.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtMacImpl : public JwtMacInternal {
 public:
  explicit JwtMacImpl(std::unique_ptr<crypto::tink::Mac> mac,
                      absl::string_view algorithm,
                      absl::optional<absl::string_view> custom_kid) {
    mac_ = std::move(mac);
    algorithm_ = std::string(algorithm);
    if (custom_kid.has_value()) {
      custom_kid_ = std::string(*custom_kid);
    }
  }

  crypto::tink::util::StatusOr<std::string> ComputeMacAndEncodeWithKid(
      const crypto::tink::RawJwt& token,
      absl::optional<absl::string_view> kid) const override;

  crypto::tink::util::StatusOr<crypto::tink::VerifiedJwt>
  VerifyMacAndDecodeWithKid(
      absl::string_view compact, const crypto::tink::JwtValidator& validator,
      absl::optional<absl::string_view> kid) const override;

 private:
  std::unique_ptr<crypto::tink::Mac> mac_;
  std::string algorithm_;
  absl::optional<std::string> custom_kid_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_MAC_IMPL_H_
