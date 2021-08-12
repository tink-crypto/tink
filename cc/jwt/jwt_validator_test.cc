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
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, NotExpiredTokenOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, TokenWithExpEqualToNowIsExpired) {
  absl::Time now = absl::FromUnixSeconds(12345);
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().SetExpiration(now).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, ClockSkewIsToLarge) {
  EXPECT_FALSE(
      JwtValidatorBuilder().SetClockSkew(absl::Minutes(11)).Build().ok());
}

TEST(JwtValidator, RecentlyExpiredTokenWithClockSkewOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now - absl::Seconds(100)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetClockSkew(absl::Seconds(200)).Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheFutureNotOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now + absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, NotBeforeInThePastOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now - absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, TokenWithNotBeforeEqualToNowIsValid) {
  absl::Time now = absl::FromUnixSeconds(12345);
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetNotBefore(now).WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetFixedNow(now).AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, NotBeforeInTheNearFutureWithClockSkewOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now + absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .AllowMissingExpiration()
                                               .SetClockSkew(absl::Seconds(200))
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, IssuedAt) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> tokenIssuedInTheFuture = RawJwtBuilder()
                                   .SetIssuedAt(now + absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(tokenIssuedInTheFuture.status(), IsOk());
  util::StatusOr<RawJwt> tokenIssuedInThePast = RawJwtBuilder()
                                   .SetIssuedAt(now - absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(tokenIssuedInThePast.status(), IsOk());
  util::StatusOr<RawJwt> tokenWithoutIssuedAt = RawJwtBuilder()
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(tokenWithoutIssuedAt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                                  .AllowMissingExpiration()
                                                  .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*tokenIssuedInTheFuture), IsOk());
  EXPECT_THAT(validator->Validate(*tokenIssuedInThePast), IsOk());
  EXPECT_THAT(validator->Validate(*tokenWithoutIssuedAt), IsOk());

  util::StatusOr<JwtValidator> issued_at_validator =
      JwtValidatorBuilder()
          .ExpectIssuedInThePast()
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(issued_at_validator.status(), IsOk());
  EXPECT_FALSE(issued_at_validator->Validate(*tokenIssuedInTheFuture).ok());
  EXPECT_THAT(issued_at_validator->Validate(*tokenIssuedInThePast), IsOk());
  EXPECT_FALSE(issued_at_validator->Validate(*tokenWithoutIssuedAt).ok());
}

TEST(JwtValidator, IssuedAtWithClockSkew) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> tokenOneMinuteInTheFuture = RawJwtBuilder()
                                   .SetIssuedAt(now + absl::Minutes(1))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(tokenOneMinuteInTheFuture.status(), IsOk());

  util::StatusOr<JwtValidator> validator_without_clock_skew =
      JwtValidatorBuilder()
          .ExpectIssuedInThePast()
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator_without_clock_skew.status(), IsOk());
  EXPECT_FALSE(
      validator_without_clock_skew->Validate(*tokenOneMinuteInTheFuture).ok());

  util::StatusOr<JwtValidator> validator_with_clock_skew =
      JwtValidatorBuilder()
          .ExpectIssuedInThePast()
          .AllowMissingExpiration()
          .SetClockSkew(absl::Minutes(2))
          .Build();
  ASSERT_THAT(validator_with_clock_skew.status(), IsOk());
  EXPECT_THAT(validator_with_clock_skew->Validate(*tokenOneMinuteInTheFuture),
              IsOk());
}

TEST(JwtValidator, RequiresTypeHeaderButNotTypHeaderNotOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, InvalidTypeHeaderNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("JWT")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, CorrectTypeHeaderOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectTypeHeader("typeHeader")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, TypeHeaderInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, IgnoreTypeHeaderOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetTypeHeader("typeHeader").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreTypeHeader().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, RequiresIssuerButNotIssuerNotOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, InvalidIssuerNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, CorrectIssuerOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, IssuerInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, IgnoreIssuerOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreIssuer().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, ExpectSubjectButNotSubjectNotOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectSubject("subject")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, InvalidSubjectNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetSubject("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectSubject("subject")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, CorrectSubjectOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetSubject("subject").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectSubject("subject")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, SubjectInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetSubject("subject").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, IgnoreSubjectOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetSubject("subject").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreSubject().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, RequiresAudienceButNotAudienceNotOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectSubject("subject")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, InvalidAudienceNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetSubject("unknown").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectAudience("audience")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, CorrectAudienceOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .AddAudience("otherAudience")
                                   .AddAudience("audience")
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectAudience("audience")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, AudienceInTokenButNotInValiatorNotOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().AddAudience("audience").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, NoAudienceOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, IgnoreAudiencesOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().AddAudience("audience").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().IgnoreAudiences().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, FixedNowExpiredNotOk) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(now + absl::Seconds(100)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder()
          .SetFixedNow(now + absl::Seconds(200))
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, FixedNowNotYetValidNotOk) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(now - absl::Seconds(100))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder()
          .SetFixedNow(now - absl::Seconds(200))
          .AllowMissingExpiration()
          .Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(validator->Validate(*jwt).ok());
}

TEST(JwtValidator, FixedNowValidOk) {
  absl::Time now = absl::FromUnixSeconds(12345);
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetExpiration(now + absl::Seconds(100))
                                   .SetNotBefore(now - absl::Seconds(100))
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().SetFixedNow(now).Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_THAT(validator->Validate(*jwt), IsOk());
}

TEST(JwtValidator, CallBuildTwiceOk) {
  JwtValidatorBuilder builder = JwtValidatorBuilder().AllowMissingExpiration();

  builder.ExpectIssuer("issuer1");
  util::StatusOr<JwtValidator> validator1 = builder.Build();
  ASSERT_THAT(validator1.status(), IsOk());

  builder.ExpectIssuer("issuer2");
  util::StatusOr<JwtValidator> validator2 = builder.Build();
  ASSERT_THAT(validator2.status(), IsOk());

  util::StatusOr<RawJwt> jwt1 =
      RawJwtBuilder().SetIssuer("issuer1").WithoutExpiration().Build();
  ASSERT_THAT(jwt1.status(), IsOk());
  util::StatusOr<RawJwt> jwt2 =
      RawJwtBuilder().SetIssuer("issuer2").WithoutExpiration().Build();
  ASSERT_THAT(jwt2.status(), IsOk());

  EXPECT_THAT(validator1->Validate(*jwt1), IsOk());
  EXPECT_FALSE(validator1->Validate(*jwt2).ok());
  EXPECT_THAT(validator2->Validate(*jwt2), IsOk());
  EXPECT_FALSE(validator2->Validate(*jwt1).ok());
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
