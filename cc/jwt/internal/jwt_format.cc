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

std::string CreateHeader(absl::string_view algorithm,
                         absl::optional<absl::string_view> type_header,
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
  util::StatusOr<std::string> json_or =
      jwt_internal::ProtoStructToJsonString(header);
  if (!json_or.ok()) {
    // do something
  }
  return EncodeHeader(json_or.ValueOrDie());
}

util::Status ValidateHeader(const google::protobuf::Struct& header,
                            absl::string_view algorithm) {
  auto fields = header.fields();
  auto it = fields.find("alg");
  if (it == fields.end()) {
    return util::Status(util::error::INVALID_ARGUMENT, "header is missing alg");
  }
  const auto& alg = it->second;
  if (alg.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT, "alg is not a string");
  }
  if (alg.string_value() != algorithm) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid alg");
  }
  if (fields.find("crit") != fields.end()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "all tokens with crit headers are rejected");
  }
  return util::OkStatus();
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

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
