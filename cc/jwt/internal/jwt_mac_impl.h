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

#include "absl/strings/string_view.h"
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

class JwtMacImpl : public JwtMac {
 public:
  explicit JwtMacImpl(std::unique_ptr<crypto::tink::Mac> mac,
                      absl::string_view algorithm) {
    mac_ = std::move(mac);
    algorithm_ = std::string(algorithm);
  }

  crypto::tink::util::StatusOr<std::string> ComputeMacAndEncode(
      const crypto::tink::RawJwt& token) const override;

  crypto::tink::util::StatusOr<crypto::tink::VerifiedJwt> VerifyMacAndDecode(
      absl::string_view compact,
      const crypto::tink::JwtValidator& validator) const override;

 private:
  std::unique_ptr<crypto::tink::Mac> mac_;
  std::string algorithm_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_MAC_IMPL_H_
