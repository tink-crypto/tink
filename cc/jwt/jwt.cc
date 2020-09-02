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

#include "tink/jwt/jwt.h"

#include "absl/strings/numbers.h"
#include "absl/strings/substitute.h"
#include "tink/jwt/jwt_names.h"

namespace crypto {
namespace tink {
util::StatusOr<std::unique_ptr<Jwt>> Jwt::New(
    const google::protobuf::Struct& header,
    const google::protobuf::Struct& payload, const absl::Time clock,
    const absl::Duration clockSkew) {
  std::unique_ptr<Jwt> jwt(new Jwt(header, payload, clock, clockSkew));
  return jwt;
}

Jwt::Jwt(const google::protobuf::Struct& header,
         const google::protobuf::Struct& payload, const absl::Time clock,
         const absl::Duration clockSkew) {
  this->header_ = header;
  this->payload_ = payload;
  this->clock_skew_ = clockSkew;
  this->clock_ = clock;
}

util::StatusOr<std::string> Jwt::GetValueAsString(
    const google::protobuf::Struct& j_proto, absl::string_view name) const {
  const auto& it = j_proto.fields().find(std::string(name));
  if (it == j_proto.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kStringValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field $0' is not a string", name));
  }

  return it->second.string_value();
}

util::StatusOr<double> Jwt::GetValueAsNumber(
    const google::protobuf::Struct& j_proto, absl::string_view name) const {
  const auto& it = j_proto.fields().find(std::string(name));
  if (it == j_proto.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kNumberValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is not a number", name));
  }

  return it->second.number_value();
}

util::StatusOr<absl::Time> Jwt::GetValueAsTime(
    const google::protobuf::Struct& j_proto, absl::string_view name) const {
  auto number_or = GetValueAsNumber(j_proto, name);
  if (!number_or.status().ok()) {
    return number_or.status();
  }

  return absl::FromUnixSeconds(number_or.ValueOrDie());
}

util::StatusOr<const google::protobuf::ListValue*> Jwt::GetValueAsList(
    const google::protobuf::Struct& j_proto, absl::string_view name) const {
  const auto& it = j_proto.fields().find(std::string(name));
  if (it == j_proto.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kListValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is not a list", name));
  }

  return static_cast<const google::protobuf::ListValue*>(
      &it->second.list_value());
}

util::StatusOr<std::vector<std::string>> Jwt::GetClaimAsStringList(
    absl::string_view name) const {
  std::vector<std::string> vec;
  auto list_or = GetValueAsList(this->payload_, name);
  if (!list_or.status().ok()) {
    return list_or.status();
  }

  auto& list = list_or.ValueOrDie();
  for (const auto& v : list->values()) {
    if (v.kind_case() != google::protobuf::Value::kStringValue) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::Substitute(
              "field '$0' contains an element that is not a string", name));
    }
    vec.push_back(v.string_value());
  }

  if (vec.empty()) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is empty", name));
  }

  return vec;
}

util::StatusOr<std::vector<double>> Jwt::GetClaimAsNumberList(
    absl::string_view name) const {
  std::vector<double> vec;
  auto list_or = GetValueAsList(this->payload_, name);
  if (!list_or.status().ok()) {
    return list_or.status();
  }

  auto list = list_or.ValueOrDie();
  for (const auto& v : list->values()) {
    if (v.kind_case() != google::protobuf::Value::kNumberValue) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::Substitute(
              "field '$0' contains an element that is not a number", name));
    }
    vec.push_back(v.number_value());
  }

  if (vec.empty()) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is empty", name));
  }

  return vec;
}

util::StatusOr<std::vector<std::string>> Jwt::GetAudiences() const {
  std::vector<std::string> vec;

  auto aud_or = GetValueAsString(this->payload_, JwtNames::kClaimAudience);
  if (aud_or.status().ok()) {
    vec.push_back(aud_or.ValueOrDie());
    return vec;
  }

  auto aud_list_or = GetValueAsList(this->payload_, JwtNames::kClaimAudience);
  if (!aud_list_or.status().ok()) {
    return aud_list_or.status();
  }

  auto aud_list = aud_list_or.ValueOrDie();
  for (const auto& v : aud_list->values()) {
    if (v.kind_case() != google::protobuf::Value::kStringValue) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::Substitute(
              "field '$0' contains an element that is not a string",
              JwtNames::kClaimAudience));
    }
    vec.push_back(v.string_value());
  }

  if (vec.empty()) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is empty", JwtNames::kClaimAudience));
  }

  return vec;
}

util::StatusOr<bool> Jwt::GetValueAsBool(
    const google::protobuf::Struct& j_proto, absl::string_view name) const {
  const auto& it = j_proto.fields().find(std::string(name));
  if (it == j_proto.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kBoolValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is not a list", name));
  }

  return it->second.bool_value();
}

util::StatusOr<double> Jwt::GetClaimAsNumber(absl::string_view name) const {
  return GetValueAsNumber(this->payload_, name);
}

util::StatusOr<bool> Jwt::GetClaimAsBool(absl::string_view name) const {
  return GetValueAsBool(this->payload_, name);
}

util::StatusOr<std::string> Jwt::GetSubject() const {
  return GetValueAsString(this->payload_, JwtNames::kClaimSubject);
}

util::StatusOr<absl::Time> Jwt::GetExpiration() const {
  return GetValueAsTime(this->payload_, JwtNames::kClaimExpiration);
}

util::StatusOr<absl::Time> Jwt::GetNotBefore() const {
  return GetValueAsTime(this->payload_, JwtNames::kClaimNotBefore);
}

util::StatusOr<absl::Time> Jwt::GetIssuedAt() const {
  return GetValueAsTime(this->payload_, JwtNames::kClaimIssuedAt);
}

util::StatusOr<std::string> Jwt::GetIssuer() const {
  return GetValueAsString(this->payload_, JwtNames::kClaimIssuer);
}

util::StatusOr<std::string> Jwt::GetJwtId() const {
  return GetValueAsString(this->payload_, JwtNames::kClaimJwtId);
}

util::StatusOr<std::string> Jwt::GetContentType() const {
  return GetValueAsString(this->header_, JwtNames::kHeaderContentType);
}

util::StatusOr<std::string> Jwt::GetAlgorithm() const {
  return GetValueAsString(this->header_, JwtNames::kHeaderAlgorithm);
}

util::StatusOr<std::string> Jwt::GetKeyId() const {
  return GetValueAsString(this->header_, JwtNames::kHeaderKeyId);
}

util::StatusOr<std::string> Jwt::GetClaimAsString(
    absl::string_view name) const {
  return GetValueAsString(this->payload_, name);
}

util::StatusOr<std::string> Jwt::GetType() const {
  return GetValueAsString(this->header_, JwtNames::kHeaderType);
}

util::Status Jwt::validateTimestampClaims() const {
  absl::Time now = this->clock_;

  auto exp_or = GetExpiration();
  if (!exp_or.status().ok() &&
      exp_or.status().error_code() != util::error::NOT_FOUND) {
    // This is an error, e.g. malformated input
    return exp_or.status();
  }

  if (exp_or.status().ok()) {
    // Validate the expiration.
    auto exp = exp_or.ValueOrDie();
    if (now > exp + this->clock_skew_) {
      return crypto::tink::util::Status(util::error::OUT_OF_RANGE,
                                        "token is expired");
    }
  }

  auto nbf_or = GetNotBefore();
  if (!nbf_or.status().ok() &&
      nbf_or.status().error_code() != util::error::NOT_FOUND) {
    // This is an error, e.g. malformated input
    return nbf_or.status();
  }

  if (nbf_or.status().ok()) {
    // Validate the nbf_or.
    auto nbf = nbf_or.ValueOrDie();
    if (now < nbf - this->clock_skew_) {
      return crypto::tink::util::Status(util::error::OUT_OF_RANGE,
                                        "token is not yet valid");
    }
  }

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
