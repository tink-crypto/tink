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

#include "tink/jwt/internal/jwt_public_key_sign_impl.h"

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
    util::StatusOr<std::string> type_or = token.GetTypeHeader();
    if (!type_or.ok()) {
      return type_or.status();
    }
    type_header = type_or.ValueOrDie();
  }
  std::string encoded_header = CreateHeader(algorithm_, type_header, kid);
  util::StatusOr<std::string> payload_or = token.GetJsonPayload();
  if (!payload_or.ok()) {
    return payload_or.status();
  }
  std::string encoded_payload = EncodePayload(payload_or.ValueOrDie());
  std::string unsigned_token =
      absl::StrCat(encoded_header, ".", encoded_payload);
  util::StatusOr<std::string> tag_or = sign_->Sign(unsigned_token);
  if (!tag_or.ok()) {
    return tag_or.status();
  }
  std::string encoded_tag = EncodeSignature(tag_or.ValueOrDie());
  return absl::StrCat(unsigned_token, ".", encoded_tag);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
