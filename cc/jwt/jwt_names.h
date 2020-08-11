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

#ifndef TINK_JWT_JWT_NAMES_H_
#define TINK_JWT_JWT_NAMES_H_

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Registered claim names, as defined in
// https://tools.ietf.org/html/rfc7519#section-4.1.
// If update, please update validateClaim().
class JwtNames {
 public:
  // Claims
  static constexpr absl::string_view kClaimIssuer = "iss";
  static constexpr absl::string_view kClaimSubject = "sub";
  static constexpr absl::string_view kClaimAudience = "aud";
  static constexpr absl::string_view kClaimExpiration = "exp";
  static constexpr absl::string_view kClaimNotBefore = "nbf";
  static constexpr absl::string_view kClaimIssuedAt = "iat";
  static constexpr absl::string_view kClaimJwtId = "jti";

  // Supported protected headers, as described in
  // https://tools.ietf.org/html/rfc7515#section-4.1
  static constexpr absl::string_view kHeaderAlgorithm = "alg";
  static constexpr absl::string_view kHeaderKeyId = "kid";
  static constexpr absl::string_view kHeaderType = "typ";
  static constexpr absl::string_view kHeaderContentType = "cty";

  virtual ~JwtNames() {}

 private:
  static util::Status validate(absl::string_view name);
  static bool isRegisteredName(absl::string_view name);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_NAMES_H_
