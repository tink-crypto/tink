// Copyright 2020 Google LLC
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
// If update, please update validateClaim() in jwt_object.cc.
constexpr absl::string_view kJwtClaimIssuer = "iss";
constexpr absl::string_view kJwtClaimSubject = "sub";
constexpr absl::string_view kJwtClaimAudience = "aud";
constexpr absl::string_view kJwtClaimExpiration = "exp";
constexpr absl::string_view kJwtClaimNotBefore = "nbf";
constexpr absl::string_view kJwtClaimIssuedAt = "iat";
constexpr absl::string_view kJwtClaimJwtId = "jti";

// Supported protected headers, as described in
// https://tools.ietf.org/html/rfc7515#section-4.1
constexpr absl::string_view kJwtHeaderAlgorithm = "alg";
constexpr absl::string_view kJwtHeaderKeyId = "kid";
constexpr absl::string_view kJwtHeaderType = "typ";
constexpr absl::string_view kJwtHeaderContentType = "cty";

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_NAMES_H_
