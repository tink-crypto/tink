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

#include "tink/jwt/jwt_object.h"

#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/substitute.h"
#include "tink/jwt/json_object.h"
#include "tink/jwt/jwt_names.h"

namespace crypto {
namespace tink {

JwtObject::JwtObject(const JsonObject& header, const JsonObject& payload) {
  header_ = header;
  payload_ = payload;
}

JwtObject::JwtObject() {}

util::StatusOr<std::vector<std::string>> JwtObject::GetClaimAsStringList(
    absl::string_view name) const {
  return payload_.GetValueAsStringList(name);
}

util::StatusOr<std::vector<int>> JwtObject::GetClaimAsNumberList(
    absl::string_view name) const {
  return payload_.GetValueAsNumberList(name);
}

util::StatusOr<std::vector<std::string>> JwtObject::GetAudiences() const {
  std::vector<std::string> vec;

  auto aud_or = payload_.GetValueAsString(kJwtClaimAudience);
  if (aud_or.status().ok()) {
    vec.push_back(aud_or.ValueOrDie());
    return vec;
  }

  return payload_.GetValueAsStringList(kJwtClaimAudience);
}

util::StatusOr<int> JwtObject::GetClaimAsNumber(absl::string_view name) const {
  return payload_.GetValueAsNumber(name);
}

util::StatusOr<bool> JwtObject::GetClaimAsBool(absl::string_view name) const {
  return payload_.GetValueAsBool(name);
}

util::StatusOr<std::string> JwtObject::GetSubject() const {
  return payload_.GetValueAsString(kJwtClaimSubject);
}

util::StatusOr<absl::Time> JwtObject::GetExpiration() const {
  return payload_.GetValueAsTime(kJwtClaimExpiration);
}

util::StatusOr<absl::Time> JwtObject::GetNotBefore() const {
  return payload_.GetValueAsTime(kJwtClaimNotBefore);
}

util::StatusOr<absl::Time> JwtObject::GetIssuedAt() const {
  return payload_.GetValueAsTime(kJwtClaimIssuedAt);
}

util::StatusOr<std::string> JwtObject::GetIssuer() const {
  return payload_.GetValueAsString(kJwtClaimIssuer);
}

util::StatusOr<std::string> JwtObject::GetJwtId() const {
  return payload_.GetValueAsString(kJwtClaimJwtId);
}

util::StatusOr<std::string> JwtObject::GetContentType() const {
  return header_.GetValueAsString(kJwtHeaderContentType);
}

util::StatusOr<enum JwtAlgorithm> JwtObject::GetAlgorithm() const {
  auto algo_or = header_.GetValueAsString(kJwtHeaderAlgorithm);
  if (algo_or.status() != util::OkStatus()) {
    return algo_or.status();
  }

  auto algo = algo_or.ValueOrDie();
  auto algo_type_or = AlgorithmStringToType(algo);
  if (algo_type_or.status() != util::OkStatus()) {
    return algo_type_or.status();
  }

  return algo_type_or.ValueOrDie();
}

util::StatusOr<std::string> JwtObject::GetKeyId() const {
  return header_.GetValueAsString(kJwtHeaderKeyId);
}

util::StatusOr<std::string> JwtObject::GetClaimAsString(
    absl::string_view name) const {
  return payload_.GetValueAsString(name);
}

util::StatusOr<std::string> JwtObject::GetType() const {
  return header_.GetValueAsString(kJwtHeaderType);
}

util::Status JwtObject::SetType(absl::string_view type) {
  return header_.SetValueAsString(kJwtHeaderType, type);
}

util::Status JwtObject::SetContentType(absl::string_view contentType) {
  return header_.SetValueAsString(kJwtHeaderContentType, contentType);
}

util::Status JwtObject::SetAlgorithm(enum JwtAlgorithm algorithm) {
  auto algo_or = AlgorithmTypeToString(algorithm);
  if (!algo_or.status().ok()) {
    return algo_or.status();
  }

  auto algo = algo_or.ValueOrDie();

  return header_.SetValueAsString(kJwtHeaderAlgorithm, algo);
}

util::Status JwtObject::SetKeyId(absl::string_view keyid) {
  return header_.SetValueAsString(kJwtHeaderKeyId, keyid);
}

util::Status JwtObject::SetIssuer(absl::string_view issuer) {
  return payload_.SetValueAsString(kJwtClaimIssuer, issuer);
}

util::Status JwtObject::SetSubject(absl::string_view subject) {
  return payload_.SetValueAsString(kJwtClaimSubject, subject);
}

util::Status JwtObject::SetJwtId(absl::string_view jwid) {
  return payload_.SetValueAsString(kJwtClaimJwtId, jwid);
}

util::Status JwtObject::SetExpiration(absl::Time expiration) {
  return payload_.SetValueAsTime(kJwtClaimExpiration, expiration);
}

util::Status JwtObject::SetNotBefore(absl::Time notBefore) {
  return payload_.SetValueAsTime(kJwtClaimNotBefore, notBefore);
}

util::Status JwtObject::SetIssuedAt(absl::Time issuedAt) {
  return payload_.SetValueAsTime(kJwtClaimIssuedAt, issuedAt);
}

util::Status JwtObject::AddAudience(absl::string_view audience) {
  return payload_.AppendValueToStringList(kJwtClaimAudience, audience);
}

util::Status JwtObject::SetClaimAsString(absl::string_view name,
                                         absl::string_view value) {
  auto status = ValidatePayloadName(name);
  if (status != util::Status::OK) {
    return status;
  }

  return payload_.SetValueAsString(name, value);
}

util::Status JwtObject::SetClaimAsNumber(absl::string_view name, int value) {
  auto status = ValidatePayloadName(name);
  if (status != util::Status::OK) {
    return status;
  }

  return payload_.SetValueAsNumber(name, value);
}

util::Status JwtObject::SetClaimAsBool(absl::string_view name, bool value) {
  auto status = ValidatePayloadName(name);
  if (status != util::Status::OK) {
    return status;
  }

  return payload_.SetValueAsBool(name, value);
}

util::Status JwtObject::AppendClaimToStringList(absl::string_view name,
                                                absl::string_view value) {
  auto status = ValidatePayloadName(name);
  if (status != util::Status::OK) {
    return status;
  }

  return payload_.AppendValueToStringList(name, value);
}

util::Status JwtObject::AppendClaimToNumberList(absl::string_view name,
                                                int value) {
  auto status = ValidatePayloadName(name);
  if (status != util::Status::OK) {
    return status;
  }

  return payload_.AppendValueToNumberList(name, value);
}

util::StatusOr<absl::string_view> JwtObject::AlgorithmTypeToString(
    const enum JwtAlgorithm algorithm) const {
  switch (algorithm) {
    case JwtAlgorithm::kHs256:
      return kJwtAlgorithmHs256;
    case JwtAlgorithm::kEs256:
      return kJwtAlgorithmEs256;
    case JwtAlgorithm::kRs256:
      return kJwtAlgorithmRs256;
    default:
      return crypto::tink::util::Status(
          util::error::UNIMPLEMENTED,
          absl::Substitute(
              "algorithm '$0' is not supported",
              static_cast<std::underlying_type<JwtAlgorithm>::type>(
                  algorithm)));
  }
}

util::StatusOr<enum JwtAlgorithm> JwtObject::AlgorithmStringToType(
    absl::string_view algo_name) const {
  if (algo_name == kJwtAlgorithmHs256) {
    return JwtAlgorithm::kHs256;
  }
  if (algo_name == kJwtAlgorithmEs256) {
    return JwtAlgorithm::kEs256;
  }
  if (algo_name == kJwtAlgorithmRs256) {
    return JwtAlgorithm::kRs256;
  }

  return crypto::tink::util::Status(
      util::error::INVALID_ARGUMENT,
      absl::Substitute("algorithm '$0' does not exist", algo_name));
}

util::Status JwtObject::ValidateHeaderName(absl::string_view name) {
  if (IsRegisteredHeaderName(name)) {
    return absl::InvalidArgumentError(absl::Substitute(
        "header '$0' is invalid because it's a registered name; "
        "use the corresponding setter method.",
        name));
  }

  return util::OkStatus();
}

util::Status JwtObject::ValidatePayloadName(absl::string_view name) {
  if (IsRegisteredPayloadName(name)) {
    return absl::InvalidArgumentError(absl::Substitute(
        "claim '$0' is invalid because it's a registered name; "
        "use the corresponding setter method.",
        name));
  }

  return util::OkStatus();
}

bool JwtObject::IsRegisteredHeaderName(absl::string_view name) {
  return name == kJwtHeaderAlgorithm || name == kJwtHeaderKeyId ||
         name == kJwtHeaderType || name == kJwtHeaderContentType;
}

bool JwtObject::IsRegisteredPayloadName(absl::string_view name) {
  return name == kJwtClaimIssuer || name == kJwtClaimSubject ||
         name == kJwtClaimAudience || name == kJwtClaimExpiration ||
         name == kJwtClaimNotBefore || name == kJwtClaimIssuedAt ||
         name == kJwtClaimJwtId;
}


}  // namespace tink
}  // namespace crypto
