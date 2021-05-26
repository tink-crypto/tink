// Copyright 2021 Google LLC.
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

#ifndef TINK_JWT_INTERNAL_JWT_PUBLIC_KEY_SIGN_IMPL_H_
#define TINK_JWT_INTERNAL_JWT_PUBLIC_KEY_SIGN_IMPL_H_

#include "absl/strings/string_view.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/public_key_sign.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtPublicKeySignImpl : public JwtPublicKeySignInternal {
 public:
  explicit JwtPublicKeySignImpl(
      std::unique_ptr<crypto::tink::PublicKeySign> sign,
      absl::string_view algorithm) {
    sign_ = std::move(sign);
    algorithm_ = std::string(algorithm);
  }

  crypto::tink::util::StatusOr<std::string> SignAndEncodeWithKid(
      const crypto::tink::RawJwt& token,
      absl::optional<absl::string_view> kid) const override;

 private:
  std::unique_ptr<crypto::tink::PublicKeySign> sign_;
  std::string algorithm_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_PUBLIC_KEY_SIGN_IMPL_H_
