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

#ifndef TINK_JWT_JWT_VALIDATOR_H_
#define TINK_JWT_JWT_VALIDATOR_H_

#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/jwt/raw_jwt.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// A JwtValidator defines how JSON Web Tokens (JWTs) should be validated.
//

class JwtValidatorBuilder;

class JwtValidator {
 public:
  // JwtValidator objects are copiable and movable.
  JwtValidator(const JwtValidator&) = default;
  JwtValidator& operator=(const JwtValidator&) = default;
  JwtValidator(JwtValidator&& other) = default;
  JwtValidator& operator=(JwtValidator&& other) = default;

  util::Status Validate(crypto::tink::RawJwt const& raw_jwt) const;

 private:
  explicit JwtValidator(const JwtValidatorBuilder& builder);
  friend class JwtValidatorBuilder;
  absl::optional<std::string> expected_type_header_;
  absl::optional<std::string> expected_issuer_;
  absl::optional<std::string> expected_subject_;
  absl::optional<std::string> expected_audience_;
  bool ignore_type_header_;
  bool ignore_issuer_;
  bool ignore_subject_;
  bool ignore_audiences_;
  absl::Duration clock_skew_;
  absl::optional<absl::Time> fixed_now_;
};

class JwtValidatorBuilder {
 public:
  JwtValidatorBuilder();

  // JwtValidatorBuilder objects are copiable and movable.
  JwtValidatorBuilder(const JwtValidatorBuilder&) = default;
  JwtValidatorBuilder& operator=(const JwtValidatorBuilder&) = default;
  JwtValidatorBuilder(JwtValidatorBuilder&& other) = default;
  JwtValidatorBuilder& operator=(JwtValidatorBuilder&& other) = default;

  JwtValidatorBuilder& ExpectTypeHeader(absl::string_view expected_type_header);
  JwtValidatorBuilder& ExpectIssuer(absl::string_view expected_issuer);
  JwtValidatorBuilder& ExpectSubject(absl::string_view expected_subject);
  JwtValidatorBuilder& ExpectAudience(absl::string_view expected_audience);

  JwtValidatorBuilder& IgnoreTypeHeader();
  JwtValidatorBuilder& IgnoreIssuer();
  JwtValidatorBuilder& IgnoreSubject();
  JwtValidatorBuilder& IgnoreAudiences();

  util::Status SetClockSkew(absl::Duration clock_skew);
  JwtValidatorBuilder& SetFixedNow(absl::Time fixed_now);

  util::StatusOr<JwtValidator> Build();

 private:
  friend class JwtValidator;
  absl::optional<std::string> expected_type_header_;
  absl::optional<std::string> expected_issuer_;
  absl::optional<std::string> expected_subject_;
  absl::optional<std::string> expected_audience_;
  bool ignore_type_header_;
  bool ignore_issuer_;
  bool ignore_subject_;
  bool ignore_audiences_;
  absl::Duration clock_skew_;
  absl::optional<absl::Time> fixed_now_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_VALIDATOR_H_
