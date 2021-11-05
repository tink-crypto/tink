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

#include "tink/jwt/internal/jwt_format.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "tink/crypto_format.h"
#include "tink/jwt/internal/json_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::google::crypto::tink::OutputPrefixType;

namespace {

bool isValidUrlsafeBase64Char(char c) {
  return (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) ||
          ((c >= '0') && (c <= '9')) || ((c == '-') || (c == '_')));
}

bool StrictWebSafeBase64Unescape(absl::string_view src, std::string* dest) {
  for (char c : src) {
    if (!isValidUrlsafeBase64Char(c)) {
      return false;
    }
  }
  return absl::WebSafeBase64Unescape(src, dest);
}

util::Status ValidateKidInHeader(const google::protobuf::Value& kid_in_header,
                                 absl::string_view kid) {
  if (kid_in_header.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "kid header is not a string");
  }
  if (kid_in_header.string_value() != kid) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "invalid kid header");
  }
  return util::OkStatus();
}

}  // namespace

std::string EncodeHeader(absl::string_view json_header) {
  return absl::WebSafeBase64Escape(json_header);
}

bool DecodeHeader(absl::string_view header, std::string* json_header) {
  return StrictWebSafeBase64Unescape(header, json_header);
}

absl::optional<std::string> GetKid(uint32_t key_id,
                                   OutputPrefixType output_prefix_type) {
  if (output_prefix_type != OutputPrefixType::TINK) {
    return absl::nullopt;
  }
  char buffer[4];
  absl::big_endian::Store32(buffer, key_id);
  return absl::WebSafeBase64Escape(absl::string_view(buffer, 4));
}

absl::optional<uint32_t> GetKeyId(absl::string_view kid) {
  std::string decoded_kid;
  if (!StrictWebSafeBase64Unescape(kid, &decoded_kid)) {
    return absl::nullopt;
  }
  if (decoded_kid.size() != 4) {
    return absl::nullopt;
  }

  return absl::big_endian::Load32(decoded_kid.data());
}

util::StatusOr<std::string> CreateHeader(
    absl::string_view algorithm, absl::optional<absl::string_view> type_header,
    absl::optional<absl::string_view> kid) {
  google::protobuf::Struct header;
  auto fields = header.mutable_fields();
  if (kid.has_value()) {
    google::protobuf::Value kid_value;
    (*fields)["kid"].set_string_value(std::string(kid.value()));
  }
  if (type_header.has_value()) {
    (*fields)["typ"].set_string_value(std::string(type_header.value()));
  }
  (*fields)["alg"].set_string_value(std::string(algorithm));
  util::StatusOr<std::string> json_header =
      jwt_internal::ProtoStructToJsonString(header);
  if (!json_header.ok()) {
    return json_header.status();
  }
  return EncodeHeader(*json_header);
}

util::Status ValidateHeader(const google::protobuf::Struct& header,
                            absl::string_view algorithm,
                            absl::optional<absl::string_view> tink_kid,
                            absl::optional<absl::string_view> custom_kid) {
  auto fields = header.fields();
  auto it = fields.find("alg");
  if (it == fields.end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "header is missing alg");
  }
  const google::protobuf::Value& alg = it->second;
  if (alg.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "alg is not a string");
  }
  if (alg.string_value() != algorithm) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid alg");
  }
  if (fields.find("crit") != fields.end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "all tokens with crit headers are rejected");
  }

  if (tink_kid.has_value() && custom_kid.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "custom_kid can only be set for RAW keys");
  }
  auto kid_it = fields.find("kid");
  bool header_has_kid = (kid_it != fields.end());
  if (tink_kid.has_value()) {
    if (!header_has_kid) {
      // for output prefix type TINK, the kid header is required.
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "missing kid in header");
    }
    util::Status status = ValidateKidInHeader(kid_it->second, *tink_kid);
    if (!status.ok()) {
      return status;
    }
  }
  if (custom_kid.has_value() && header_has_kid) {
    util::Status status = ValidateKidInHeader(kid_it->second, *custom_kid);
    if (!status.ok()) {
      return status;
    }
  }
  return util::OkStatus();
}

// TODO(juerg): Remove this function once it is not used anymore.
util::Status ValidateHeader(const google::protobuf::Struct& header,
                            absl::string_view algorithm) {
  return ValidateHeader(header, algorithm, absl::nullopt, absl::nullopt);
}

absl::optional<std::string> GetTypeHeader(
    const google::protobuf::Struct& header) {
  auto it = header.fields().find("typ");
  if (it == header.fields().end()) {
    return absl::nullopt;
  }
  const auto& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return absl::nullopt;
  }
  return value.string_value();
}

std::string EncodePayload(absl::string_view json_payload) {
  return absl::WebSafeBase64Escape(json_payload);
}

bool DecodePayload(absl::string_view payload, std::string* json_payload) {
  return StrictWebSafeBase64Unescape(payload, json_payload);
}

std::string EncodeSignature(absl::string_view signature) {
  return absl::WebSafeBase64Escape(signature);
}

bool DecodeSignature(absl::string_view encoded_signature,
                     std::string* signature) {
  return StrictWebSafeBase64Unescape(encoded_signature, signature);
}

util::StatusOr<RawJwt> RawJwtParser::FromJson(
    absl::optional<std::string> type_header, absl::string_view json_payload) {
  return RawJwt::FromJson(type_header, json_payload);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
