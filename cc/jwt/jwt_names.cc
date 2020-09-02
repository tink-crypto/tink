// Copyright 2017 Google Inc.
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

#include "tink/jwt/jwt_names.h"

namespace crypto {
namespace tink {

constexpr absl::string_view JwtNames::kClaimIssuer;
constexpr absl::string_view JwtNames::kClaimSubject;
constexpr absl::string_view JwtNames::kClaimAudience;
constexpr absl::string_view JwtNames::kClaimExpiration;
constexpr absl::string_view JwtNames::kClaimNotBefore;
constexpr absl::string_view JwtNames::kClaimIssuedAt;
constexpr absl::string_view JwtNames::kClaimJwtId;

constexpr absl::string_view JwtNames::kHeaderAlgorithm;
constexpr absl::string_view JwtNames::kHeaderKeyId;
constexpr absl::string_view JwtNames::kHeaderType;
constexpr absl::string_view JwtNames::kHeaderContentType;

util::Status JwtNames::validate(absl::string_view name) {
  if (isRegisteredName(name)) {
    return absl::InvalidArgumentError(
        absl::StrFormat("claim '%s' is invalid because it's a registered name; "
                        "use the corresponding setter method.",
                        name));
  }

  return util::Status::OK;
}

bool JwtNames::isRegisteredName(absl::string_view name) {
  return name == kClaimIssuer || name == kClaimSubject ||
         name == kClaimAudience || name == kClaimExpiration ||
         name == kClaimNotBefore || name == kClaimIssuedAt ||
         name == kClaimJwtId;
}

}  // namespace tink
}  // namespace crypto
