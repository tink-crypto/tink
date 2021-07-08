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

#include "tink/jwt/raw_jwt.h"

#include <string>
#include <utility>

#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"
#include "tink/jwt/internal/json_util.h"

namespace crypto {
namespace tink {

namespace {

// Registered claim names, as defined in
// https://tools.ietf.org/html/rfc7519#section-4.1.
constexpr absl::string_view kJwtClaimIssuer = "iss";
constexpr absl::string_view kJwtClaimSubject = "sub";
constexpr absl::string_view kJwtClaimAudience = "aud";
constexpr absl::string_view kJwtClaimExpiration = "exp";
constexpr absl::string_view kJwtClaimNotBefore = "nbf";
constexpr absl::string_view kJwtClaimIssuedAt = "iat";
constexpr absl::string_view kJwtClaimJwtId = "jti";

constexpr int64_t kJwtTimestampMax = 253402300799;  // 31 Dec 9999, 23:59:59 GMT

bool IsRegisteredClaimName(absl::string_view name) {
  return name == kJwtClaimIssuer || name == kJwtClaimSubject ||
         name == kJwtClaimAudience || name == kJwtClaimExpiration ||
         name == kJwtClaimNotBefore || name == kJwtClaimIssuedAt ||
         name == kJwtClaimJwtId;
}

util::Status ValidatePayloadName(absl::string_view name) {
  if (IsRegisteredClaimName(name)) {
    return absl::InvalidArgumentError(absl::Substitute(
        "claim '$0' is invalid because it's a registered name; "
        "use the corresponding getter or setter method.",
        name));
  }
  return util::OkStatus();
}

bool HasClaimOfKind(const google::protobuf::Struct& json_proto,
                    absl::string_view name,
                    google::protobuf::Value::KindCase kind) {
  if (IsRegisteredClaimName(name)) {
    return false;
  }
  auto fields = json_proto.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return false;
  }
  const google::protobuf::Value& value = it->second;
  return value.kind_case() == kind;
}

// Returns true if the claim is present but not a string.
bool ClaimIsNotAString(const google::protobuf::Struct& json_proto,
                       absl::string_view name) {
  auto fields = json_proto.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return false;
  }
  const auto& value = it->second;
  return value.kind_case() != google::protobuf::Value::kStringValue;
}

// Returns true if the claim is present but not a timestamp.
bool ClaimIsNotATimestamp(const google::protobuf::Struct& json_proto,
                          absl::string_view name) {
  auto fields = json_proto.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return false;
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return true;
  }
  double timestamp = value.number_value();
  return (timestamp > kJwtTimestampMax) || (timestamp < 0);
}

int64_t TimeToTimestamp(absl::Time time) {
  // We round the timestamp to a whole number. We always round down.
  return absl::ToUnixSeconds(time);
}

absl::Time TimestampToTime(double timestamp) {
  if (timestamp > kJwtTimestampMax) {
    return absl::FromUnixSeconds(kJwtTimestampMax);
  }
  return absl::FromUnixSeconds(timestamp);
}

util::Status ValidateAndFixAudienceClaim(google::protobuf::Struct* json_proto) {
  auto fields = json_proto->mutable_fields();
  auto it = fields->find(std::string(kJwtClaimAudience));
  if (it == fields->end()) {
    return util::OkStatus();
  }
  google::protobuf::Value& value = it->second;
  if (value.kind_case() == google::protobuf::Value::kStringValue) {
    std::string aud = value.string_value();
    value.mutable_list_value()->add_values()->set_string_value(aud);
    return util::OkStatus();
  }
  if (value.kind_case() != google::protobuf::Value::kListValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "aud claim is not a list");
  }
  if (value.list_value().values_size() < 1) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "aud claim is present but empty");
  }
  for (const auto& v : value.list_value().values()) {
    if (v.kind_case() != google::protobuf::Value::kStringValue) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "aud claim is not a list of strings");
    }
  }
  return util::OkStatus();
}

}  // namespace

util::StatusOr<RawJwt> RawJwt::FromJson(absl::optional<std::string> type_header,
                                        absl::string_view json_payload) {
  util::StatusOr<google::protobuf::Struct> proto =
      jwt_internal::JsonStringToProtoStruct(json_payload);
  if (!proto.ok()) {
    return proto.status();
  }
  if (ClaimIsNotAString(*proto, kJwtClaimIssuer) ||
      ClaimIsNotAString(*proto, kJwtClaimSubject) ||
      ClaimIsNotATimestamp(*proto, kJwtClaimExpiration) ||
      ClaimIsNotATimestamp(*proto, kJwtClaimNotBefore) ||
      ClaimIsNotATimestamp(*proto, kJwtClaimIssuedAt)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "contains an invalid registered claim");
  }
  util::Status aud_status = ValidateAndFixAudienceClaim(&(*proto));
  if (!aud_status.ok()) {
    return aud_status;
  }
  RawJwt token(type_header, *std::move(proto));
  return token;
}

util::StatusOr<std::string> RawJwt::GetJsonPayload() const {
  return jwt_internal::ProtoStructToJsonString(json_proto_);
}

RawJwt::RawJwt() {}

RawJwt::RawJwt(absl::optional<std::string> type_header,
               google::protobuf::Struct json_proto) {
  type_header_ = type_header;
  json_proto_ = json_proto;
}

bool RawJwt::HasTypeHeader() const { return type_header_.has_value(); }

util::StatusOr<std::string> RawJwt::GetTypeHeader() const {
  if (!type_header_.has_value()) {
    return util::Status(util::error::INVALID_ARGUMENT, "No type header found");
  }
  return *type_header_;
}

bool RawJwt::HasIssuer() const {
  return json_proto_.fields().contains(std::string(kJwtClaimIssuer));
}

util::StatusOr<std::string> RawJwt::GetIssuer() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimIssuer));
  if (it == fields.end()) {
    return util::Status(util::error::INVALID_ARGUMENT, "No Issuer found");
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Issuer is not a string");
  }
  return value.string_value();
}

bool RawJwt::HasSubject() const {
  return json_proto_.fields().contains(std::string(kJwtClaimSubject));
}

util::StatusOr<std::string> RawJwt::GetSubject() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimSubject));
  if (it == fields.end()) {
    return util::Status(util::error::INVALID_ARGUMENT, "No Subject found");
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Subject is not a string");
  }
  return value.string_value();
}

bool RawJwt::HasAudiences() const {
  return json_proto_.fields().contains(std::string(kJwtClaimAudience));
}

util::StatusOr<std::vector<std::string>> RawJwt::GetAudiences() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimAudience));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND, "No Audiences found");
  }
  google::protobuf::Value list = it->second;
  if (list.kind_case() != google::protobuf::Value::kListValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Audiences is not a list");
  }
  std::vector<std::string> audiences;
  for (const auto& value : list.list_value().values()) {
    if (value.kind_case() != google::protobuf::Value::kStringValue) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "Audiences is not a list of strings");
    }
    audiences.push_back(value.string_value());
  }
  return audiences;
}


bool RawJwt::HasJwtId() const {
  return json_proto_.fields().contains(std::string(kJwtClaimJwtId));
}

util::StatusOr<std::string> RawJwt::GetJwtId() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimJwtId));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND, "No JwtId found");
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT, "JwtId is not a string");
  }
  return value.string_value();
}

bool RawJwt::HasExpiration() const {
  return json_proto_.fields().contains(std::string(kJwtClaimExpiration));
}

util::StatusOr<absl::Time> RawJwt::GetExpiration() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimExpiration));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND, "No Expiration found");
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Expiration is not a number");
  }
  return TimestampToTime(value.number_value());
}

bool RawJwt::HasNotBefore() const {
  return json_proto_.fields().contains(std::string(kJwtClaimNotBefore));
}

util::StatusOr<absl::Time> RawJwt::GetNotBefore() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimNotBefore));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND, "No NotBefore found");
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "NotBefore is not a number");
  }
  return TimestampToTime(value.number_value());
}

bool RawJwt::HasIssuedAt() const {
  return json_proto_.fields().contains(std::string(kJwtClaimIssuedAt));
}

util::StatusOr<absl::Time> RawJwt::GetIssuedAt() const {
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(kJwtClaimIssuedAt));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND, "No IssuedAt found");
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "IssuedAt is not a number");
  }
  return TimestampToTime(value.number_value());
}

bool RawJwt::IsNullClaim(absl::string_view name) const {
  return HasClaimOfKind(json_proto_, name, google::protobuf::Value::kNullValue);
}

bool RawJwt::HasBooleanClaim(absl::string_view name) const {
  return HasClaimOfKind(json_proto_, name, google::protobuf::Value::kBoolValue);
}

util::StatusOr<bool> RawJwt::GetBooleanClaim(
    absl::string_view name) const {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kBoolValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::Substitute("claim '$0' is not a bool", name));
  }
  return value.bool_value();
}

bool RawJwt::HasStringClaim(absl::string_view name) const {
  return HasClaimOfKind(json_proto_, name,
                        google::protobuf::Value::kStringValue);
}

util::StatusOr<std::string> RawJwt::GetStringClaim(
    absl::string_view name) const {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::Substitute("claim '$0' is not a string", name));
  }
  return value.string_value();
}

bool RawJwt::HasNumberClaim(absl::string_view name) const {
  return HasClaimOfKind(json_proto_, name,
                        google::protobuf::Value::kNumberValue);
}

util::StatusOr<double> RawJwt::GetNumberClaim(absl::string_view name) const {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::Substitute("claim '$0' is not a number", name));
  }
  return value.number_value();
}

bool RawJwt::HasJsonObjectClaim(absl::string_view name) const {
  return HasClaimOfKind(json_proto_, name,
                        google::protobuf::Value::kStructValue);
}

util::StatusOr<std::string> RawJwt::GetJsonObjectClaim(
    absl::string_view name) const {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kStructValue) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("claim '$0' is not a JSON object", name));
  }
  return jwt_internal::ProtoStructToJsonString(value.struct_value());
}

bool RawJwt::HasJsonArrayClaim(absl::string_view name) const {
  return HasClaimOfKind(json_proto_, name,
                        google::protobuf::Value::kListValue);
}

util::StatusOr<std::string> RawJwt::GetJsonArrayClaim(
    absl::string_view name) const {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const google::protobuf::Value& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kListValue) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("claim '$0' is not a JSON array", name));
  }
  return jwt_internal::ProtoListToJsonString(value.list_value());
}

std::vector<std::string> RawJwt::CustomClaimNames() const {
  auto fields = json_proto_.fields();
  std::vector<std::string> values;
  for (auto it = fields.begin(); it != fields.end(); it++) {
    if (!IsRegisteredClaimName(it->first)) {
      values.push_back(it->first);
    }
  }
  return values;
}

RawJwtBuilder::RawJwtBuilder() { without_expiration_ = false; }

RawJwtBuilder& RawJwtBuilder::SetTypeHeader(absl::string_view type_header) {
  type_header_ = std::string(type_header);
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetIssuer(absl::string_view issuer) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_string_value(std::string(issuer));
  (*fields)[std::string(kJwtClaimIssuer)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetSubject(absl::string_view subject) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_string_value(std::string(subject));
  (*fields)[std::string(kJwtClaimSubject)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddAudience(absl::string_view audience) {
  auto fields = json_proto_.mutable_fields();
  auto insertion_result = fields->insert(
      {std::string(kJwtClaimAudience), google::protobuf::Value()});
  google::protobuf::ListValue* list_value =
      insertion_result.first->second.mutable_list_value();
  list_value->add_values()->set_string_value(std::string(audience));
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetJwtId(absl::string_view jwid) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_string_value(std::string(jwid));
  (*fields)[std::string(kJwtClaimJwtId)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::WithoutExpiration() {
  without_expiration_ = true;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetExpiration(absl::Time expiration) {
  int64_t exp_timestamp = TimeToTimestamp(expiration);
  if ((exp_timestamp > kJwtTimestampMax) || (exp_timestamp < 0)) {
    if (!error_.has_value()) {
      error_ = util::Status(util::error::INVALID_ARGUMENT,
                            "invalid expiration timestamp");
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(exp_timestamp);
  (*fields)[std::string(kJwtClaimExpiration)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetNotBefore(absl::Time not_before) {
  int64_t nbf_timestamp = TimeToTimestamp(not_before);
  if ((nbf_timestamp > kJwtTimestampMax) || (nbf_timestamp < 0)) {
    if (!error_.has_value()) {
      error_ = util::Status(util::error::INVALID_ARGUMENT,
                            "invalid not_before timestamp");
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(nbf_timestamp);
  (*fields)[std::string(kJwtClaimNotBefore)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetIssuedAt(absl::Time issued_at) {
  int64_t iat_timestamp = TimeToTimestamp(issued_at);
  if ((iat_timestamp > kJwtTimestampMax) || (iat_timestamp < 0)) {
    if (!error_.has_value()) {
      error_ = util::Status(util::error::INVALID_ARGUMENT,
                            "invalid issued_at timestamp");
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(iat_timestamp);
  (*fields)[std::string(kJwtClaimIssuedAt)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddNullClaim(absl::string_view name) {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    if (!error_.has_value()) {
      error_ = status;
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_null_value(google::protobuf::NULL_VALUE);
  (*fields)[std::string(name)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddBooleanClaim(absl::string_view name,
                                              bool bool_value) {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    if (!error_.has_value()) {
      error_ = status;
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_bool_value(bool_value);
  (*fields)[std::string(name)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddStringClaim(absl::string_view name,
                                             absl::string_view string_value) {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    if (!error_.has_value()) {
      error_ = status;
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_string_value(std::string(string_value));
  (*fields)[std::string(name)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddNumberClaim(absl::string_view name,
                                             double double_value) {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    if (!error_.has_value()) {
      error_ = status;
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(double_value);
  (*fields)[std::string(name)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddJsonObjectClaim(
    absl::string_view name, absl::string_view object_value) {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    if (!error_.has_value()) {
      error_ = status;
    }
    return *this;
  }
  util::StatusOr<google::protobuf::Struct> proto =
      jwt_internal::JsonStringToProtoStruct(object_value);
  if (!proto.ok()) {
    if (!error_.has_value()) {
      error_ = proto.status();
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  *value.mutable_struct_value() = *std::move(proto);
  (*fields)[std::string(name)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::AddJsonArrayClaim(absl::string_view name,
                                                absl::string_view array_value) {
  util::Status status = ValidatePayloadName(name);
  if (!status.ok()) {
    if (!error_.has_value()) {
      error_ = status;
    }
    return *this;
  }
  util::StatusOr<google::protobuf::ListValue> list =
      jwt_internal::JsonStringToProtoList(array_value);
  if (!list.ok()) {
    if (!error_.has_value()) {
      error_ = list.status();
    }
    return *this;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  *value.mutable_list_value() = *list;
  (*fields)[std::string(name)] = value;
  return *this;
}

util::StatusOr<RawJwt> RawJwtBuilder::Build() {
  if (error_.has_value()) {
    return *error_;
  }
  if (!json_proto_.fields().contains(std::string(kJwtClaimExpiration)) &&
      !without_expiration_) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "neither SetExpiration() nor WithoutExpiration() was called");
  }
  if (json_proto_.fields().contains(std::string(kJwtClaimExpiration)) &&
      without_expiration_) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "SetExpiration() and WithoutExpiration() must not be called together");
  }
  RawJwt token(type_header_, json_proto_);
  return token;
}

}  // namespace tink
}  // namespace crypto
