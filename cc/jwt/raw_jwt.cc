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
  const auto& value = it->second;
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
  const auto& value = it->second;
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return true;
  }
  double timestamp = value.number_value();
  return (timestamp > kJwtTimestampMax) || (timestamp < 0);
}

util::StatusOr<double> TimeToTimestamp(absl::Time time) {
  double millis = absl::ToUnixMillis(time);
  double timestamp = millis / 1000;
  if ((timestamp > kJwtTimestampMax) || (timestamp < 0)) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid timestamp");
  }
  return timestamp;
}

absl::Time TimestampToTime(double timestamp) {
  if (timestamp > kJwtTimestampMax) {
    return absl::FromUnixMillis(kJwtTimestampMax * 1000);
  }
  int64_t millis = timestamp * 1000;
  return absl::FromUnixMillis(millis);
}

util::Status ValidateAndFixAudienceClaim(google::protobuf::Struct* json_proto) {
  auto fields = json_proto->mutable_fields();
  auto it = fields->find(std::string(kJwtClaimAudience));
  if (it == fields->end()) {
    return util::OkStatus();
  }
  auto& value = it->second;
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

util::StatusOr<RawJwt> RawJwt::FromString(absl::string_view json_string) {
  auto proto_or = jwt_internal::JsonStringToProtoStruct(json_string);
  if (!proto_or.ok()) {
    return proto_or.status();
  }
  auto& proto = proto_or.ValueOrDie();
  if (ClaimIsNotAString(proto, kJwtClaimIssuer) ||
      ClaimIsNotAString(proto, kJwtClaimSubject) ||
      ClaimIsNotATimestamp(proto, kJwtClaimExpiration) ||
      ClaimIsNotATimestamp(proto, kJwtClaimNotBefore) ||
      ClaimIsNotATimestamp(proto, kJwtClaimIssuedAt)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "contains an invalid registered claim");
  }
  auto audStatus = ValidateAndFixAudienceClaim(&proto);
  if (!audStatus.ok()) {
    return audStatus;
  }
  RawJwt token(proto);
  return token;
}

util::StatusOr<std::string> RawJwt::ToString() const {
  return jwt_internal::ProtoStructToJsonString(json_proto_);
}

RawJwt::RawJwt() {}

RawJwt::RawJwt(google::protobuf::Struct json_proto) {
  json_proto_ = json_proto;
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
  const auto& value = it->second;
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
  const auto& value = it->second;
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
  auto list = it->second;
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
  const auto& value = it->second;
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
  const auto& value = it->second;
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
  const auto& value = it->second;
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
  const auto& value = it->second;
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
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const auto& value = it->second;
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
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const auto& value = it->second;
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
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const auto& value = it->second;
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
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const auto& value = it->second;
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
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.fields();
  auto it = fields.find(std::string(name));
  if (it == fields.end()) {
    return util::Status(util::error::NOT_FOUND,
                        absl::Substitute("claim '$0' not found", name));
  }
  const auto& value = it->second;
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

RawJwtBuilder::RawJwtBuilder() {}

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
  auto list_value = insertion_result.first->second.mutable_list_value();
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

util::Status RawJwtBuilder::SetExpiration(absl::Time expiration) {
  util::StatusOr<double> timestamp_or = TimeToTimestamp(expiration);
  if (!timestamp_or.ok()) {
    return timestamp_or.status();
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(timestamp_or.ValueOrDie());
  (*fields)[std::string(kJwtClaimExpiration)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::SetNotBefore(absl::Time notBefore) {
  util::StatusOr<double> timestamp_or = TimeToTimestamp(notBefore);
  if (!timestamp_or.ok()) {
    return timestamp_or.status();
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(timestamp_or.ValueOrDie());
  (*fields)[std::string(kJwtClaimNotBefore)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::SetIssuedAt(absl::Time issuedAt) {
  util::StatusOr<double> timestamp_or = TimeToTimestamp(issuedAt);
  if (!timestamp_or.ok()) {
    return timestamp_or.status();
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(timestamp_or.ValueOrDie());
  (*fields)[std::string(kJwtClaimIssuedAt)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::AddNullClaim(absl::string_view name) {
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_null_value(google::protobuf::NULL_VALUE);
  (*fields)[std::string(name)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::AddBooleanClaim(absl::string_view name,
                                            bool bool_value) {
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_bool_value(bool_value);
  (*fields)[std::string(name)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::AddStringClaim(absl::string_view name,
                                           std::string string_value) {
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_string_value(string_value);
  (*fields)[std::string(name)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::AddNumberClaim(absl::string_view name,
                                           double double_value) {
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(double_value);
  (*fields)[std::string(name)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::AddJsonObjectClaim(absl::string_view name,
                                               absl::string_view object_value) {
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto proto_or = jwt_internal::JsonStringToProtoStruct(object_value);
  if (!proto_or.ok()) {
    return proto_or.status();
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  *value.mutable_struct_value() = proto_or.ValueOrDie();
  (*fields)[std::string(name)] = value;
  return util::OkStatus();
}

util::Status RawJwtBuilder::AddJsonArrayClaim(absl::string_view name,
                                              absl::string_view array_value) {
  auto status = ValidatePayloadName(name);
  if (!status.ok()) {
    return status;
  }
  auto list_or = jwt_internal::JsonStringToProtoList(array_value);
  if (!list_or.ok()) {
    return list_or.status();
  }
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  *value.mutable_list_value() = list_or.ValueOrDie();
  (*fields)[std::string(name)] = value;
  return util::OkStatus();
}

util::StatusOr<RawJwt> RawJwtBuilder::Build() {
  RawJwt token(json_proto_);
  return token;
}

}  // namespace tink
}  // namespace crypto
