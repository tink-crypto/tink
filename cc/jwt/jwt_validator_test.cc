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
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, NotExpiredTokenOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now + absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, TokenWithExpEqualToNowIsExpired) {
  absl::Time now = absl::FromUnixSeconds(12345);
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, ClockSkewIsToLarge) {
  JwtValidatorBuilder builder = JwtValidatorBuilder();
  EXPECT_FALSE(builder.SetClockSkew(absl::Minutes(11)).ok());
}

TEST(JwtValidator, RecentlyExpiredTokenWithClockSkewOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidatorBuilder builder = JwtValidatorBuilder();
  ASSERT_THAT(builder.SetClockSkew(absl::Seconds(200)), IsOk());
  util::StatusOr<JwtValidator> validator_or = builder.Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheFutureNotOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetNotBefore(now + absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, NotBeforeInThePastOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetNotBefore(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, TokenWithNotBeforeEqualToNowIsValid) {
  absl::Time now = absl::FromUnixSeconds(12345);
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetNotBefore(now), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheNearFutureWithClockSkewOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetNotBefore(now + absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  JwtValidatorBuilder builder = JwtValidatorBuilder();
  ASSERT_THAT(builder.SetClockSkew(absl::Seconds(200)), IsOk());
  util::StatusOr<JwtValidator> validator_or = builder.Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresIssuerButNotIssuerNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectIssuer("issuer").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidIssuerNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("unknown").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectIssuer("issuer").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectIssuerOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectIssuer("issuer").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, IssuerInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, IgnoreIssuerOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreIssuer().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresSubjectButNotSubjectNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectSubject("subject").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidSubjectNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("unknown").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectSubject("subject").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectSubjectOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("subject").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectSubject("subject").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, SubjectInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("subject").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, IgnoreSubjectOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("subject").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreSubject().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresAudienceButNotAudienceNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectSubject("subject").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidAudienceNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().SetSubject("unknown").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectAudience("audience").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectAudienceOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder()
                    .AddAudience("otherAudience")
                    .AddAudience("audience")
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectAudience("audience").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, AudienceInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().AddAudience("audience").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, NoAudienceOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, IgnoreAudienceOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().AddAudience("audience").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreAudience().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, FixedNowExpiredNotOk) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now + absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetFixedNow(now + absl::Seconds(200)).Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, FixedNowNotYetValidNotOk) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetNotBefore(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetFixedNow(now - absl::Seconds(200)).Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, FixedNowValidOk) {
  absl::Time now = absl::FromUnixSeconds(12345);
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now + absl::Seconds(100)), IsOk());
  ASSERT_THAT(jwt_builder.SetNotBefore(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, CallBuildTwiceOk) {
  JwtValidatorBuilder builder = JwtValidatorBuilder();

  builder.ExpectIssuer("issuer1");
  util::StatusOr<JwtValidator> validator1_or = builder.Build();
  ASSERT_THAT(validator1_or.status(), IsOk());

  builder.ExpectIssuer("issuer2");
  util::StatusOr<JwtValidator> validator2_or = builder.Build();
  ASSERT_THAT(validator2_or.status(), IsOk());

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

  EXPECT_THAT(validator1_or.ValueOrDie().Validate(jwt1), IsOk());
  EXPECT_FALSE(validator1_or.ValueOrDie().Validate(jwt2).ok());
  EXPECT_THAT(validator2_or.ValueOrDie().Validate(jwt2), IsOk());
  EXPECT_FALSE(validator2_or.ValueOrDie().Validate(jwt1).ok());
}

TEST(JwtValidator, InvalidValidators) {
  EXPECT_FALSE(
      JwtValidatorBuilder().ExpectIssuer("a").IgnoreIssuer().Build().ok());
  EXPECT_FALSE(
      JwtValidatorBuilder().ExpectSubject("a").IgnoreSubject().Build().ok());
  EXPECT_FALSE(
      JwtValidatorBuilder().ExpectAudience("a").IgnoreAudience().Build().ok());
}


}  // namespace tink
}  // namespace crypto
