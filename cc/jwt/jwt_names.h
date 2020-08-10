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
  inline static const char* claim_issuer_ = "iss";
  inline static const char* claim_subject_ = "sub";
  inline static const char* claim_audience_ = "aud";
  inline static const char* claim_expiration_ = "exp";
  inline static const char* claim_not_before_ = "nbf";
  inline static const char* claim_issued_at_ = "iat";
  inline static const char* claim_jwt_id_ = "jti";

  // Supported protected headers, as described in
  // https://tools.ietf.org/html/rfc7515#section-4.1
  inline static const char* header_algorithm_ = "alg";
  inline static const char* header_key_id_ = "kid";
  inline static const char* header_type_ = "typ";
  inline static const char* header_content_type_ = "cty";

  virtual ~JwtNames() {}

 private:
  static util::Status validate(absl::string_view name);
  static bool isRegisteredName(absl::string_view name);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_NAMES_H_
