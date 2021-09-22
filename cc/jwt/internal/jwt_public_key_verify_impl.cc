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

#include "tink/jwt/internal/jwt_public_key_verify_impl.h"

#include <string>
#include <utility>

#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

util::StatusOr<VerifiedJwt> JwtPublicKeyVerifyImpl::VerifyAndDecodeWithKid(
    absl::string_view compact, const JwtValidator& validator,
    absl::optional<absl::string_view> kid) const {
  // TODO(juerg): Refactor this code into a util function.
  std::size_t signature_pos = compact.find_last_of('.');
  if (signature_pos == absl::string_view::npos) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid token");
  }
  absl::string_view unsigned_token = compact.substr(0, signature_pos);
  std::string signature;
  if (!DecodeSignature(compact.substr(signature_pos + 1), &signature)) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid JWT signature");
  }
  util::Status verify_result = verify_->Verify(signature, unsigned_token);
  if (!verify_result.ok()) {
    // Use a different error code so that we can distinguish it.
    return util::Status(util::error::UNAUTHENTICATED,
                        verify_result.error_message());
  }
  std::vector<absl::string_view> parts = absl::StrSplit(unsigned_token, '.');
  if (parts.size() != 2) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "only tokens in JWS compact serialization format are supported");
  }
  std::string json_header;
  if (!DecodeHeader(parts[0], &json_header)) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid header");
  }
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  if (!header.ok()) {
    return header.status();
  }
  util::Status validate_header_result =
      ValidateHeader(*header, algorithm_, kid, custom_kid_);
  if (!validate_header_result.ok()) {
    return validate_header_result;
  }
  std::string json_payload;
  if (!DecodePayload(parts[1], &json_payload)) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid JWT payload");
  }
  util::StatusOr<RawJwt> raw_jwt = RawJwtParser::FromJson(
      GetTypeHeader(*header), json_payload);
  if (!raw_jwt.ok()) {
    return raw_jwt.status();
  }
  util::Status validate_result = validator.Validate(*raw_jwt);
  if (!validate_result.ok()) {
    return validate_result;
  }
  return VerifiedJwt(*std::move(raw_jwt));
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
