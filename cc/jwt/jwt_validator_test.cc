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
  EXPECT_FALSE(
      JwtValidatorBuilder().SetClockSkew(absl::Minutes(11)).Build().ok());
}

TEST(JwtValidator, RecentlyExpiredTokenWithClockSkewOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder();
  ASSERT_THAT(jwt_builder.SetExpiration(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetClockSkew(absl::Seconds(200)).Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheFutureNotOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(jwt_builder.SetNotBefore(now + absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, NotBeforeInThePastOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(jwt_builder.SetNotBefore(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, TokenWithNotBeforeEqualToNowIsValid) {
  absl::Time now = absl::FromUnixSeconds(12345);
  auto jwt_builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(jwt_builder.SetNotBefore(now), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().SetFixedNow(now).AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheNearFutureWithClockSkewOK) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(jwt_builder.SetNotBefore(now + absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder()
          .AllowMissingExpiration()
          .SetClockSkew(absl::Seconds(200))
          .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresTypeHeaderButNotTypHeaderNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidTypeHeaderNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetTypeHeader("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectTypeHeader("JWT")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectTypeHeaderOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder()
          .ExpectTypeHeader("typeHeader")
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, TypeHeaderInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, IgnoreTypeHeaderOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreTypeHeader().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresIssuerButNotIssuerNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectIssuer("issuer")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidIssuerNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetIssuer("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectIssuer("issuer")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectIssuerOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectIssuer("issuer")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, IssuerInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, IgnoreIssuerOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreIssuer().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresSubjectButNotSubjectNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectSubject("subject")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidSubjectNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetSubject("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectSubject("subject")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectSubjectOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetSubject("subject").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectSubject("subject")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, SubjectInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetSubject("subject").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, IgnoreSubjectOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetSubject("subject").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreSubject().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, RequiresAudienceButNotAudienceNotOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectSubject("subject")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, InvalidAudienceNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().SetSubject("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectAudience("audience")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, CorrectAudienceOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder()
                                      .AddAudience("otherAudience")
                                      .AddAudience("audience")
                                      .WithoutExpiration()
                                      .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or = JwtValidatorBuilder()
                                                  .ExpectAudience("audience")
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, AudienceInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().AddAudience("audience").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, NoAudienceOK) {
  util::StatusOr<RawJwt> jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_THAT(validator_or.ValueOrDie().Validate(jwt), IsOk());
}

TEST(JwtValidator, IgnoreAudiencesOK) {
  util::StatusOr<RawJwt> jwt_or =
      RawJwtBuilder().AddAudience("audience").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder().IgnoreAudiences().AllowMissingExpiration().Build();
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
      JwtValidatorBuilder()
          .SetFixedNow(now + absl::Seconds(200))
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator_or.status(), IsOk());
  EXPECT_FALSE(validator_or.ValueOrDie().Validate(jwt).ok());
}

TEST(JwtValidator, FixedNowNotYetValidNotOk) {
  absl::Time now = absl::Now();
  auto jwt_builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(jwt_builder.SetNotBefore(now - absl::Seconds(100)), IsOk());
  util::StatusOr<RawJwt> jwt_or = jwt_builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  util::StatusOr<JwtValidator> validator_or =
      JwtValidatorBuilder()
          .SetFixedNow(now - absl::Seconds(200))
          .AllowMissingExpiration()
          .Build();
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
  JwtValidatorBuilder builder = JwtValidatorBuilder().AllowMissingExpiration();

  builder.ExpectIssuer("issuer1");
  util::StatusOr<JwtValidator> validator1_or = builder.Build();
  ASSERT_THAT(validator1_or.status(), IsOk());

  builder.ExpectIssuer("issuer2");
  util::StatusOr<JwtValidator> validator2_or = builder.Build();
  ASSERT_THAT(validator2_or.status(), IsOk());

  util::StatusOr<RawJwt> jwt1_or =
      RawJwtBuilder().SetIssuer("issuer1").WithoutExpiration().Build();
  ASSERT_THAT(jwt1_or.status(), IsOk());
  RawJwt jwt1 = jwt1_or.ValueOrDie();
  util::StatusOr<RawJwt> jwt2_or =
      RawJwtBuilder().SetIssuer("issuer2").WithoutExpiration().Build();
  ASSERT_THAT(jwt2_or.status(), IsOk());
  RawJwt jwt2 = jwt2_or.ValueOrDie();

  EXPECT_THAT(validator1_or.ValueOrDie().Validate(jwt1), IsOk());
  EXPECT_FALSE(validator1_or.ValueOrDie().Validate(jwt2).ok());
  EXPECT_THAT(validator2_or.ValueOrDie().Validate(jwt2), IsOk());
  EXPECT_FALSE(validator2_or.ValueOrDie().Validate(jwt1).ok());
}

TEST(JwtValidator, InvalidValidators) {
  EXPECT_FALSE(JwtValidatorBuilder()
                   .ExpectTypeHeader("a")
                   .IgnoreTypeHeader()
                   .AllowMissingExpiration()
                   .Build()
                   .ok());
  EXPECT_FALSE(JwtValidatorBuilder()
                   .ExpectIssuer("a")
                   .IgnoreIssuer()
                   .AllowMissingExpiration()
                   .Build()
                   .ok());
  EXPECT_FALSE(JwtValidatorBuilder()
                   .ExpectSubject("a")
                   .IgnoreSubject()
                   .AllowMissingExpiration()
                   .Build()
                   .ok());
  EXPECT_FALSE(JwtValidatorBuilder()
                   .ExpectAudience("a")
                   .IgnoreAudiences()
                   .AllowMissingExpiration()
                   .Build()
                   .ok());
}


}  // namespace tink
}  // namespace crypto
