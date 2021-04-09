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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_validator.h"


#include "tink/jwt/raw_jwt.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;

namespace crypto {
namespace tink {

TEST(JwtValidator, ExpiredTokenNotOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetExpiration(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, NotExpiredTokenOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetExpiration(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, ClockSkewIsToLarge) {
  JwtValidatorBuilder builder = JwtValidatorBuilder();
  EXPECT_FALSE(builder.SetClockSkew(absl::Minutes(11)).ok());
}

TEST(JwtValidator, RecentlyExpiredTokenWithClockSkewOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetExpiration(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidatorBuilder builder = JwtValidatorBuilder();
  ASSERT_THAT(builder.SetClockSkew(absl::Seconds(200)), IsOk());
  JwtValidator validator = builder.Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheFutureNotOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetNotBefore(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, NotBeforeInThePastOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetNotBefore(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheNearFutureWithClockSkewOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetNotBefore(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidatorBuilder builder = JwtValidatorBuilder();
  ASSERT_THAT(builder.SetClockSkew(absl::Seconds(200)), IsOk());
  JwtValidator validator = builder.Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresIssuerButNotIssuerNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetIssuer("issuer").Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, InvalidIssuerNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("unknown").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetIssuer("issuer").Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, CorrectIssuerOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetIssuer("issuer").Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, DontCheckIssuerOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresSubjectButNotSubjectNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetSubject("subject").Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, InvalidSubjectNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("unknown").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetSubject("subject").Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, CorrectSubjectOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("subject").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetSubject("subject").Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, DontCheckSubjectOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("subject").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresAudienceButNotAudienceNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetSubject("subject").Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, InvalidAudienceNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("unknown").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator =
      JwtValidatorBuilder().SetAudience("audience").Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, CorrectAudienceOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder()
                    .AddAudience("otherAudience")
                    .AddAudience("audience")
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator =
      JwtValidatorBuilder().SetAudience("audience").Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, AudienceInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().AddAudience("audience").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, NoAudienceOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}

TEST(JwtValidator, FixedNowExpiredNotOk) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetExpiration(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator =
      JwtValidatorBuilder().SetFixedNow(now + absl::Seconds(200)).Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, FixedNowNotYetValidNotOk) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetNotBefore(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator =
      JwtValidatorBuilder().SetFixedNow(now - absl::Seconds(200)).Build();

  EXPECT_FALSE(validator.Validate(jwt).ok());
}

TEST(JwtValidator, FixedNowValidOk) {
  absl::Time now = absl::FromUnixSeconds(12345);
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder()
      .SetExpiration(now + absl::Seconds(100))
      .SetNotBefore(now - absl::Seconds(100))
      .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetFixedNow(now).Build();

  EXPECT_THAT(validator.Validate(jwt), IsOk());
}


TEST(JwtValidator, CallBuildTwiceOk) {
  JwtValidatorBuilder builder = JwtValidatorBuilder();

  builder.SetIssuer("issuer1");
  JwtValidator validator1 = builder.Build();

  builder.SetIssuer("issuer2");
  JwtValidator validator2 = builder.Build();

  util::StatusOr<RawJwt> jwt1_or = RawJwtBuilder()
                    .SetIssuer("issuer1")
                    .Build();
  ASSERT_THAT(jwt1_or.status(), IsOk());
  RawJwt jwt1 = jwt1_or.ValueOrDie();
  util::StatusOr<RawJwt> jwt2_or = RawJwtBuilder()
                    .SetIssuer("issuer2")
                    .Build();
  ASSERT_THAT(jwt2_or.status(), IsOk());
  RawJwt jwt2 = jwt2_or.ValueOrDie();


  EXPECT_THAT(validator1.Validate(jwt1), IsOk());
  EXPECT_FALSE(validator1.Validate(jwt2).ok());
  EXPECT_THAT(validator2.Validate(jwt2), IsOk());
  EXPECT_FALSE(validator2.Validate(jwt1).ok());
}


}  // namespace tink
}  // namespace crypto
