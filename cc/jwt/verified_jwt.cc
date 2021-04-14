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

#include "tink/jwt/verified_jwt.h"

#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/substitute.h"
#include "tink/jwt/internal/json_util.h"

namespace crypto {
namespace tink {

VerifiedJwt::VerifiedJwt() {}

VerifiedJwt::VerifiedJwt(const RawJwt& raw_jwt) {
  raw_jwt_ = raw_jwt;
}

bool VerifiedJwt::HasIssuer() const {
  return raw_jwt_.HasIssuer();
}

util::StatusOr<std::string> VerifiedJwt::GetIssuer() const {
  return raw_jwt_.GetIssuer();
}

bool VerifiedJwt::HasSubject() const {
  return raw_jwt_.HasSubject();
}

util::StatusOr<std::string> VerifiedJwt::GetSubject() const {
  return raw_jwt_.GetSubject();
}

bool VerifiedJwt::HasAudiences() const {
  return raw_jwt_.HasAudiences();
}

util::StatusOr<std::vector<std::string>> VerifiedJwt::GetAudiences() const {
  return raw_jwt_.GetAudiences();
}

bool VerifiedJwt::HasJwtId() const {
  return raw_jwt_.HasJwtId();
}

util::StatusOr<std::string> VerifiedJwt::GetJwtId() const {
  return raw_jwt_.GetJwtId();
}

bool VerifiedJwt::HasExpiration() const {
  return raw_jwt_.HasExpiration();
}

util::StatusOr<absl::Time> VerifiedJwt::GetExpiration() const {
  return raw_jwt_.GetExpiration();
}

bool VerifiedJwt::HasNotBefore() const {
  return raw_jwt_.HasNotBefore();
}

util::StatusOr<absl::Time> VerifiedJwt::GetNotBefore() const {
  return raw_jwt_.GetNotBefore();
}

bool VerifiedJwt::HasIssuedAt() const {
  return raw_jwt_.HasIssuedAt();
}

util::StatusOr<absl::Time> VerifiedJwt::GetIssuedAt() const {
  return raw_jwt_.GetIssuedAt();
}

bool VerifiedJwt::IsNullClaim(absl::string_view name) const {
  return raw_jwt_.IsNullClaim(name);
}

bool VerifiedJwt::HasBooleanClaim(absl::string_view name) const {
  return raw_jwt_.HasBooleanClaim(name);
}

util::StatusOr<bool> VerifiedJwt::GetBooleanClaim(
    absl::string_view name) const {
  return raw_jwt_.GetBooleanClaim(name);
}

bool VerifiedJwt::HasStringClaim(absl::string_view name) const {
  return raw_jwt_.HasStringClaim(name);
}

util::StatusOr<std::string> VerifiedJwt::GetStringClaim(
    absl::string_view name) const {
  return raw_jwt_.GetStringClaim(name);
}

bool VerifiedJwt::HasNumberClaim(absl::string_view name) const {
  return raw_jwt_.HasNumberClaim(name);
}

util::StatusOr<double> VerifiedJwt::GetNumberClaim(
    absl::string_view name) const {
  return raw_jwt_.GetNumberClaim(name);
}

bool VerifiedJwt::HasJsonObjectClaim(absl::string_view name) const {
  return raw_jwt_.HasJsonObjectClaim(name);
}

util::StatusOr<std::string> VerifiedJwt::GetJsonObjectClaim(
    absl::string_view name) const {
  return raw_jwt_.GetJsonObjectClaim(name);
}

bool VerifiedJwt::HasJsonArrayClaim(absl::string_view name) const {
  return raw_jwt_.HasJsonArrayClaim(name);
}

util::StatusOr<std::string> VerifiedJwt::GetJsonArrayClaim(
    absl::string_view name) const {
  return raw_jwt_.GetJsonArrayClaim(name);
}

std::vector<std::string> VerifiedJwt::CustomClaimNames() const {
  return raw_jwt_.CustomClaimNames();
}

util::StatusOr<std::string> VerifiedJwt::ToString() {
  return raw_jwt_.ToString();
}

}  // namespace tink
}  // namespace crypto
