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

#include "tink/jwt/internal/jwt_public_key_sign_impl.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/jwt_format.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

util::StatusOr<std::string> JwtPublicKeySignImpl::SignAndEncodeWithKid(
    const RawJwt& token, absl::optional<absl::string_view> kid) const {
  absl::optional<std::string> type_header;
  if (token.HasTypeHeader()) {
    util::StatusOr<std::string> type = token.GetTypeHeader();
    if (!type.ok()) {
      return type.status();
    }
    type_header = *type;
  }
  if (custom_kid_.has_value()) {
    if (kid.has_value()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "TINK keys are not allowed to have a kid value set.");
    }
    kid = *custom_kid_;
  }
  util::StatusOr<std::string> encoded_header =
      CreateHeader(algorithm_, type_header, kid);
  if (!encoded_header.ok()) {
    return encoded_header.status();
  }
  util::StatusOr<std::string> payload = token.GetJsonPayload();
  if (!payload.ok()) {
    return payload.status();
  }
  std::string encoded_payload = EncodePayload(*payload);
  std::string unsigned_token =
      absl::StrCat(*encoded_header, ".", encoded_payload);
  util::StatusOr<std::string> tag = sign_->Sign(unsigned_token);
  if (!tag.ok()) {
    return tag.status();
  }
  std::string encoded_tag = EncodeSignature(*tag);
  return absl::StrCat(unsigned_token, ".", encoded_tag);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
