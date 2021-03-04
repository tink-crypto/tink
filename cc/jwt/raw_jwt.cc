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
#include "tink/jwt/jwt_names.h"
#include "tink/jwt/internal/json_util.h"

namespace crypto {
namespace tink {

util::StatusOr<RawJwt> RawJwt::FromString(absl::string_view json_string) {
  auto proto_or = JsonStringToProtoStruct(json_string);
  if (!proto_or.ok()) {
    return proto_or.status();
  }
  RawJwt token(proto_or.ValueOrDie());
  return token;
}

util::StatusOr<std::string> RawJwt::ToString() {
  return ProtoStructToJsonString(json_proto_);
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
  if (!fields.contains(std::string(kJwtClaimIssuer))) {
    return util::Status(util::error::INVALID_ARGUMENT, "No Issuer found");
  }
  auto value = fields[std::string(kJwtClaimIssuer)];
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
  if (!fields.contains(std::string(kJwtClaimSubject))) {
    return util::Status(util::error::INVALID_ARGUMENT, "No Subject found");
  }
  auto value = fields[std::string(kJwtClaimSubject)];
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Subject is not a string");
  }
  return fields[std::string(kJwtClaimSubject)].string_value();
}

bool RawJwt::HasJwtId() const {
  return json_proto_.fields().contains(std::string(kJwtClaimJwtId));
}

util::StatusOr<std::string> RawJwt::GetJwtId() const {
  auto fields = json_proto_.fields();
  if (!fields.contains(std::string(kJwtClaimJwtId))) {
    return util::Status(util::error::INVALID_ARGUMENT, "No JwtId found");
  }
  auto value = fields[std::string(kJwtClaimJwtId)];
  if (value.kind_case() != google::protobuf::Value::kStringValue) {
    return util::Status(util::error::INVALID_ARGUMENT, "JwtId is not a string");
  }
  return fields[std::string(kJwtClaimJwtId)].string_value();
}

bool RawJwt::HasExpiration() const {
  return json_proto_.fields().contains(std::string(kJwtClaimExpiration));
}

util::StatusOr<absl::Time> RawJwt::GetExpiration() const {
  auto fields = json_proto_.fields();
  if (!fields.contains(std::string(kJwtClaimExpiration))) {
    return util::Status(util::error::INVALID_ARGUMENT, "No Expiration found");
  }
  auto value = fields[std::string(kJwtClaimExpiration)];
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Expiration is not a number");
  }
  double sec = fields[std::string(kJwtClaimExpiration)].number_value();
  return absl::FromUnixSeconds(sec);
}

bool RawJwt::HasNotBefore() const {
  return json_proto_.fields().contains(std::string(kJwtClaimNotBefore));
}

util::StatusOr<absl::Time> RawJwt::GetNotBefore() const {
  auto fields = json_proto_.fields();
  if (!fields.contains(std::string(kJwtClaimNotBefore))) {
    return util::Status(util::error::INVALID_ARGUMENT, "No NotBefore found");
  }
  auto value = fields[std::string(kJwtClaimNotBefore)];
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "NotBefore is not a number");
  }
  double sec = fields[std::string(kJwtClaimNotBefore)].number_value();
  return absl::FromUnixSeconds(sec);
}

bool RawJwt::HasIssuedAt() const {
  return json_proto_.fields().contains(std::string(kJwtClaimIssuedAt));
}

util::StatusOr<absl::Time> RawJwt::GetIssuedAt() const {
  auto fields = json_proto_.fields();
  if (!fields.contains(std::string(kJwtClaimIssuedAt))) {
    return util::Status(util::error::INVALID_ARGUMENT, "No IssuedAt found");
  }
  auto value = fields[std::string(kJwtClaimIssuedAt)];
  if (value.kind_case() != google::protobuf::Value::kNumberValue) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "IssuedAt is not a number");
  }
  double sec = fields[std::string(kJwtClaimIssuedAt)].number_value();
  return absl::FromUnixSeconds(sec);
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

RawJwtBuilder& RawJwtBuilder::SetJwtId(absl::string_view jwid) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_string_value(std::string(jwid));
  (*fields)[std::string(kJwtClaimJwtId)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetExpiration(absl::Time expiration) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(static_cast<int>(absl::ToUnixSeconds(expiration)));
  (*fields)[std::string(kJwtClaimExpiration)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetNotBefore(absl::Time notBefore) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(static_cast<int>(absl::ToUnixSeconds(notBefore)));
  (*fields)[std::string(kJwtClaimNotBefore)] = value;
  return *this;
}

RawJwtBuilder& RawJwtBuilder::SetIssuedAt(absl::Time issuedAt) {
  auto fields = json_proto_.mutable_fields();
  google::protobuf::Value value;
  value.set_number_value(static_cast<int>(absl::ToUnixSeconds(issuedAt)));
  (*fields)[std::string(kJwtClaimIssuedAt)] = value;
  return *this;
}

util::StatusOr<RawJwt> RawJwtBuilder::Build() {
  RawJwt token(json_proto_);
  return token;
}

}  // namespace tink
}  // namespace crypto
