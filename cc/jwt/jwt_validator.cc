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

JwtValidator::JwtValidator(absl::optional<absl::string_view> issuer,
                           absl::optional<absl::string_view> subject,
                           absl::optional<absl::string_view> audience,
                           absl::Duration clock_skew,
                           absl::optional<absl::Time> fixed_now) {
  if (issuer.has_value()) {
    issuer_ = std::string(issuer.value());
  }
  if (subject.has_value()) {
    subject_ = std::string(subject.value());
  }
  if (audience.has_value()) {
    audience_ = std::string(audience.value());
  }
  clock_skew_ = clock_skew;
  fixed_now_ = fixed_now;
}

util::Status JwtValidator::Validate(RawJwt const& raw_jwt) const {
  absl::Time now;
  if (fixed_now_.has_value()) {
    now = fixed_now_.value();
  } else {
    now = absl::Now();
  }
  if (raw_jwt.HasExpiration()) {
    auto expiration_or = raw_jwt.GetExpiration();
    if (!expiration_or.ok()) {
      return expiration_or.status();
    }
    if (expiration_or.ValueOrDie() < now - clock_skew_) {
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
  if (issuer_.has_value()){
    if (!raw_jwt.HasIssuer()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected issuer");
    }
    auto issuer_or = raw_jwt.GetIssuer();
    if (!issuer_or.ok()) {
      return issuer_or.status();
    }
    if (issuer_.value() != issuer_or.ValueOrDie()) {
      return util::Status(util::error::INVALID_ARGUMENT, "wrong issuer");
    }
  }
  if (subject_.has_value()) {
    if (!raw_jwt.HasSubject()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected subject");
    }
    auto subject_or = raw_jwt.GetSubject();
    if (!subject_or.ok()) {
      return subject_or.status();
    }
    if (subject_.value() != subject_or.ValueOrDie()) {
      return util::Status(util::error::INVALID_ARGUMENT, "wrong subject");
    }
  }
  if (audience_.has_value()) {
    if (!raw_jwt.HasAudiences()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "missing expected audiences");
    }
    auto audiences_or = raw_jwt.GetAudiences();
    if (!audiences_or.ok()) {
      return audiences_or.status();
    }
    std::vector<std::string> audiences = audiences_or.ValueOrDie();
    auto it = std::find(audiences.begin(), audiences.end(), audience_);
    if (it == audiences.end()) {
      return util::Status(util::error::INVALID_ARGUMENT, "audience not found");
    }
  } else {
    if (raw_jwt.HasAudiences()) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "invalid JWT; token has audience set, but validator not");
    }
  }
  return util::OkStatus();
}

JwtValidatorBuilder::JwtValidatorBuilder() {
  clock_skew_ = absl::ZeroDuration();
}

JwtValidatorBuilder& JwtValidatorBuilder::SetIssuer(absl::string_view issuer) {
  issuer_ = std::string(issuer);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::SetSubject(
    absl::string_view subject) {
  subject_ = std::string(subject);
  return *this;
}

JwtValidatorBuilder& JwtValidatorBuilder::SetAudience(
    absl::string_view audience) {
  audience_ = std::string(audience);
  return *this;
}

util::Status JwtValidatorBuilder::SetClockSkew(
    absl::Duration clock_skew) {
  if (clock_skew > kJwtMaxClockSkew) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "clock skew too large, max is 10 minutes");
  }
  clock_skew_ = clock_skew;
  return util::OkStatus();
}

JwtValidatorBuilder& JwtValidatorBuilder::SetFixedNow(absl::Time fixed_now) {
  fixed_now_ = fixed_now;
  return *this;
}

JwtValidator JwtValidatorBuilder::Build() {
  JwtValidator validator(issuer_, subject_, audience_, clock_skew_, fixed_now_);
  return validator;
}

}  // namespace tink
}  // namespace crypto

