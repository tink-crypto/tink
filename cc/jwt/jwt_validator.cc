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

#include "tink/jwt/jwt_validator.h"

namespace crypto {
namespace tink {

namespace {

static constexpr absl::Duration kJwtMaxClockSkew = absl::Minutes(10);

}

JwtValidator::JwtValidator(const JwtValidatorBuilder& builder) {
  expected_type_header_ = builder.expected_type_header_;
  expected_issuer_ = builder.expected_issuer_;
  expected_subject_ = builder.expected_subject_;
  expected_audience_ = builder.expected_audience_;
  ignore_type_header_ = builder.ignore_type_header_;
  ignore_issuer_ = builder.ignore_issuer_;
  ignore_subject_ = builder.ignore_subject_;
  ignore_audiences_ = builder.ignore_audiences_;
  allow_missing_expiration_ = builder.allow_missing_expiration_;
  clock_skew_ = builder.clock_skew_;
  fixed_now_ = builder.fixed_now_;
}

util::Status JwtValidator::Validate(RawJwt const& raw_jwt) const {
  absl::Time now;
  if (fixed_now_.has_value()) {
    now = fixed_now_.value();
  } else {
    now = absl::Now();
  }
  if (!raw_jwt.HasExpiration() && !allow_missing_expiration_) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "token does not have an expiration set");
  }
  if (raw_jwt.HasExpiration()) {
    auto expiration_or = raw_jwt.GetExpiration();
    if (!expiration_or.ok()) {
      return expiration_or.status();
    }
    if (expiration_or.ValueOrDie() <= now - clock_skew_) {
      return util::Status(util::error::INVALID_ARGUMENT, "token has expired");
    }
  }
  if (raw_jwt.HasNotBefore()) {
    auto not_before_or = raw_jwt.GetNotBefore();
    if (!not_before_or.ok()) {
      return not_before_or.status();
    }
    if (not_before_or.ValueOrDie() > now + clock_skew_) {
      return util::Status(util::error::INVALID_ARGUMENT,
                        "token cannot yet be used");
    }
  }
  if (expected_type_header_.has_value()) {
    if (!raw_jwt.HasTypeHeader()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected type header");
    }
    auto type_header_or = raw_jwt.GetTypeHeader();
    if (!type_header_or.ok()) {
      return type_header_or.status();
    }
    if (expected_type_header_.value() != type_header_or.ValueOrDie()) {
      return util::Status(util::error::INVALID_ARGUMENT, "wrong type header");
    }
  } else {
    if (raw_jwt.HasTypeHeader() && !ignore_type_header_) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "invalid JWT; token has type header set, but validator not");
    }
  }
  if (expected_issuer_.has_value()){
    if (!raw_jwt.HasIssuer()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected issuer");
    }
    auto issuer_or = raw_jwt.GetIssuer();
    if (!issuer_or.ok()) {
      return issuer_or.status();
    }
    if (expected_issuer_.value() != issuer_or.ValueOrDie()) {
      return util::Status(util::error::INVALID_ARGUMENT, "wrong issuer");
    }
  } else {
    if (raw_jwt.HasIssuer() && !ignore_issuer_) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "invalid JWT; token has issuer set, but validator not");
    }
  }
  if (expected_subject_.has_value()) {
    if (!raw_jwt.HasSubject()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected subject");
    }
    auto subject_or = raw_jwt.GetSubject();
    if (!subject_or.ok()) {
      return subject_or.status();
    }
    if (expected_subject_.value() != subject_or.ValueOrDie()) {
      return util::Status(util::error::INVALID_ARGUMENT, "wrong subject");
    }
  } else {
    if (raw_jwt.HasSubject() && !ignore_subject_) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "invalid JWT; token has subject set, but validator not");
    }
  }
  if (expected_audience_.has_value()) {
    if (!raw_jwt.HasAudiences()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected audiences");
    }
    auto audiences_or = raw_jwt.GetAudiences();
    if (!audiences_or.ok()) {
      return audiences_or.status();
    }
    std::vector<std::string> audiences = audiences_or.ValueOrDie();
    auto it = std::find(audiences.begin(), audiences.end(), expected_audience_);
    if (it == audiences.end()) {
      return util::Status(util::error::INVALID_ARGUMENT, "audience not found");
    }
  } else {
    if (raw_jwt.HasAudiences() && !ignore_audiences_) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "invalid JWT; token has audience set, but validator not");
    }
  }
  return util::OkStatus();
}

JwtValidatorBuilder::JwtValidatorBuilder() {
  ignore_type_header_ = false;
  ignore_issuer_ = false;
  ignore_subject_ = false;
  ignore_audiences_ = false;
  allow_missing_expiration_ = false;
  clock_skew_ = absl::ZeroDuration();
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectTypeHeader(
    absl::string_view type_header) {
  expected_type_header_ = std::string(type_header);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectIssuer(
    absl::string_view issuer) {
  expected_issuer_ = std::string(issuer);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectSubject(
    absl::string_view subject) {
  expected_subject_ = std::string(subject);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::ExpectAudience(
    absl::string_view audience) {
  expected_audience_ = std::string(audience);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreTypeHeader() {
  ignore_type_header_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreIssuer() {
  ignore_issuer_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreSubject() {
  ignore_subject_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::IgnoreAudiences() {
  ignore_audiences_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::AllowMissingExpiration() {
  allow_missing_expiration_ = true;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::SetClockSkew(
    absl::Duration clock_skew) {
  clock_skew_ = clock_skew;
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::SetFixedNow(absl::Time fixed_now) {
  fixed_now_ = fixed_now;
  return *this;
}

util::StatusOr<JwtValidator> JwtValidatorBuilder::Build() {
  if (expected_type_header_.has_value() && ignore_type_header_) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "IgnoreTypeHeader() and ExpectTypeHeader() cannot be used together");
  }
  if (expected_issuer_.has_value() && ignore_issuer_) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "IgnoreIssuer() and ExpectedIssuer() cannot be used together");
  }
  if (expected_subject_.has_value() && ignore_subject_) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "IgnoreSubject() and ExpectSubject() cannot be used together");
  }
  if (expected_audience_.has_value() && ignore_audiences_) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "IgnoreAudiences() and ExpectAudience() cannot be used together");
  }
  if (clock_skew_ > kJwtMaxClockSkew) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "clock skew too large, max is 10 minutes");
  }
  JwtValidator validator(*this);
  return validator;
}

}  // namespace tink
}  // namespace crypto

