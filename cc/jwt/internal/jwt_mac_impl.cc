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

#include "tink/jwt/internal/jwt_mac_impl.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

util::StatusOr<std::string> JwtMacImpl::ComputeMacAndEncodeWithKid(
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
  util::StatusOr<std::string> tag = mac_->ComputeMac(unsigned_token);
  if (!tag.ok()) {
    return tag.status();
  }
  std::string encoded_tag = EncodeSignature(*tag);
  return absl::StrCat(unsigned_token, ".", encoded_tag);
}

util::StatusOr<VerifiedJwt> JwtMacImpl::VerifyMacAndDecodeWithKid(
    absl::string_view compact, const JwtValidator& validator,
    absl::optional<absl::string_view> kid) const {
  std::size_t mac_pos = compact.find_last_of('.');
  if (mac_pos == absl::string_view::npos) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid token");
  }
  absl::string_view unsigned_token = compact.substr(0, mac_pos);
  std::string mac_value;
  if (!DecodeSignature(compact.substr(mac_pos + 1), &mac_value)) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid JWT MAC");
  }
  util::Status verify_result = mac_->VerifyMac(mac_value, unsigned_token);
  if (!verify_result.ok()) {
    // Use a different error code so that we can distinguish it.
    return util::Status(absl::StatusCode::kUnauthenticated,
                        verify_result.message());
  }
  std::vector<absl::string_view> parts = absl::StrSplit(unsigned_token, '.');
  if (parts.size() != 2) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "only tokens in JWS compact serialization format are supported");
  }
  std::string json_header;
  if (!DecodeHeader(parts[0], &json_header)) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid header");
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
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "invalid JWT payload");
  }
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtParser::FromJson(GetTypeHeader(*header), json_payload);
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
