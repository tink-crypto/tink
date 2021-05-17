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

#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

util::StatusOr<std::string> JwtMacImpl::ComputeMacAndEncode(
    const RawJwt& token) const {
  absl::optional<std::string> type_header;
  if (token.HasTypeHeader()) {
    util::StatusOr<std::string> type_or = token.GetTypeHeader();
    if (!type_or.ok()) {
      return type_or.status();
    }
    type_header = type_or.ValueOrDie();
  }
  std::string encoded_header = CreateHeader(algorithm_, type_header);
  util::StatusOr<std::string> payload_or = token.GetJsonPayload();
  if (!payload_or.ok()) {
    return payload_or.status();
  }
  std::string encoded_payload = EncodePayload(payload_or.ValueOrDie());
  std::string unsigned_token =
      absl::StrCat(encoded_header, ".", encoded_payload);
  util::StatusOr<std::string> tag_or = mac_->ComputeMac(unsigned_token);
  if (!tag_or.ok()) {
    return tag_or.status();
  }
  std::string encoded_tag = EncodeSignature(tag_or.ValueOrDie());
  return absl::StrCat(unsigned_token, ".", encoded_tag);
}

util::StatusOr<VerifiedJwt> JwtMacImpl::VerifyMacAndDecode(
    absl::string_view compact, const JwtValidator& validator) const {
  std::size_t mac_pos = compact.find_last_of('.');
  if (mac_pos == absl::string_view::npos) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid token");
  }
  absl::string_view unsigned_token = compact.substr(0, mac_pos);
  std::string mac_value;
  if (!DecodeSignature(compact.substr(mac_pos + 1), &mac_value)) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid JWT MAC");
  }
  util::Status verify_result = mac_->VerifyMac(mac_value, unsigned_token);
  if (!verify_result.ok()) {
    return verify_result;
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
  auto header_or = JsonStringToProtoStruct(json_header);
  if (!header_or.ok()) {
    return header_or.status();
  }
  util::Status validate_header_result =
      ValidateHeader(header_or.ValueOrDie(), algorithm_);
  if (!validate_header_result.ok()) {
    return validate_header_result;
  }
  std::string json_payload;
  if (!DecodePayload(parts[1], &json_payload)) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid JWT payload");
  }
  auto raw_jwt_or =
      RawJwt::FromJson(GetTypeHeader(header_or.ValueOrDie()), json_payload);
  if (!raw_jwt_or.ok()) {
    return raw_jwt_or.status();
  }
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();
  util::Status validate_result = validator.Validate(raw_jwt);
  if (!validate_result.ok()) {
    return validate_result;
  }
  return VerifiedJwt(raw_jwt);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
