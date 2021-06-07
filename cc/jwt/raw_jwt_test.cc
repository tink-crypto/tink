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

#include "tink/jwt/raw_jwt.h"

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/time/time.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::UnorderedElementsAreArray;

namespace crypto {
namespace tink {

TEST(RawJwt, GetTypeHeaderIssuerSubjectJwtIdOK) {
  auto jwt_or = RawJwtBuilder()
                    .SetTypeHeader("typeHeader")
                    .SetIssuer("issuer")
                    .SetSubject("subject")
                    .SetJwtId("jwt_id")
                    .WithoutExpiration()
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasTypeHeader());
  EXPECT_THAT(jwt.GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_TRUE(jwt.HasIssuer());
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt.HasSubject());
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_TRUE(jwt.HasJwtId());
  EXPECT_THAT(jwt.GetJwtId(), IsOkAndHolds("jwt_id"));
}

TEST(RawJwt, TimestampsOK) {
  absl::Time nbf = absl::FromUnixSeconds(1234567890);
  absl::Time iat = absl::FromUnixSeconds(1234567891);
  absl::Time exp = absl::FromUnixSeconds(1234567892);
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetNotBefore(nbf), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(iat), IsOk());
  ASSERT_THAT(builder.SetExpiration(exp), IsOk());
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasNotBefore());
  auto nbf_or = jwt.GetNotBefore();
  ASSERT_THAT(nbf_or.status(), IsOk());
  EXPECT_THAT(nbf_or.ValueOrDie(), Eq(nbf));

  EXPECT_TRUE(jwt.HasIssuedAt());
  auto iat_or = jwt.GetIssuedAt();
  ASSERT_THAT(iat_or.status(), IsOk());
  EXPECT_THAT(iat_or.ValueOrDie(), Eq(iat));

  EXPECT_TRUE(jwt.HasExpiration());
  auto exp_or = jwt.GetExpiration();
  ASSERT_THAT(exp_or.status(), IsOk());
  EXPECT_THAT(exp_or.ValueOrDie(), Eq(exp));
}

TEST(RawJwt, ExpWithMillisAlwaysRoundDown) {
  absl::Time exp = absl::FromUnixMillis(123999);
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetExpiration(exp), IsOk());
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasExpiration());
  auto exp_or = jwt.GetExpiration();
  ASSERT_THAT(exp_or.status(), IsOk());
  EXPECT_THAT(exp_or.ValueOrDie(), Eq(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, NbfWithMillisAlwaysRoundDown) {
  absl::Time nbf = absl::FromUnixMillis(123999);
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetNotBefore(nbf), IsOk());
  auto jwt_or = builder.WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasNotBefore());
  auto nbf_or = jwt.GetNotBefore();
  ASSERT_THAT(nbf_or.status(), IsOk());
  EXPECT_THAT(nbf_or.ValueOrDie(), Eq(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, IatWithMillisAlwaysRoundDown) {
  absl::Time iat = absl::FromUnixMillis(123999);
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetIssuedAt(iat), IsOk());
  auto jwt_or = builder.WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasIssuedAt());
  auto iat_or = jwt.GetIssuedAt();
  ASSERT_THAT(iat_or.status(), IsOk());
  EXPECT_THAT(iat_or.ValueOrDie(), Eq(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, LargeExpirationWorks) {
  absl::Time large = absl::FromUnixSeconds(253402300799);  // year 9999
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetExpiration(large), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(large), IsOk());
  ASSERT_THAT(builder.SetNotBefore(large), IsOk());
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasExpiration());
  EXPECT_TRUE(jwt.HasIssuedAt());
  EXPECT_TRUE(jwt.HasNotBefore());
  EXPECT_THAT(jwt.GetExpiration().ValueOrDie(), Eq(large));
  EXPECT_THAT(jwt.GetIssuedAt().ValueOrDie(), Eq(large));
  EXPECT_THAT(jwt.GetNotBefore().ValueOrDie(), Eq(large));
}

TEST(RawJwt, TooLargeTimestampsFail) {
  absl::Time too_large = absl::FromUnixSeconds(253402300800);  // year 10000
  auto builder = RawJwtBuilder();
  EXPECT_FALSE(builder.SetExpiration(too_large).ok());
  EXPECT_FALSE(builder.SetIssuedAt(too_large).ok());
  EXPECT_FALSE(builder.SetNotBefore(too_large).ok());
}

TEST(RawJwt, NegativeTimestampsFail) {
  absl::Time neg = absl::FromUnixMillis(-1);
  auto builder = RawJwtBuilder();
  EXPECT_FALSE(builder.SetExpiration(neg).ok());
  EXPECT_FALSE(builder.SetIssuedAt(neg).ok());
  EXPECT_FALSE(builder.SetNotBefore(neg).ok());
}

TEST(RawJwt, SetExpirationAndWithoutExpirationFail) {
  absl::Time exp = absl::FromUnixMillis(12345);
  auto builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(builder.SetExpiration(exp), IsOk());
  EXPECT_FALSE(builder.Build().ok());
}

TEST(RawJwt, NeitherSetExpirationNorWithoutExpirationFail) {
  EXPECT_FALSE(RawJwtBuilder().Build().ok());
}

TEST(RawJwt, AddGetAudiencesOK) {
  auto jwt_or = RawJwtBuilder()
                    .AddAudience("audience1")
                    .AddAudience("audience2")
                    .WithoutExpiration()
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  std::vector<std::string> expected = {"audience1", "audience2"};
  EXPECT_TRUE(jwt.HasAudiences());
  EXPECT_THAT(jwt.GetAudiences(), IsOkAndHolds(expected));
}

TEST(RawJwt, GetCustomClaimOK) {
  auto builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(builder.AddNullClaim("null_claim"), IsOk());
  ASSERT_THAT(builder.AddBooleanClaim("boolean_claim", true), IsOk());
  ASSERT_THAT(builder.AddNumberClaim("number_claim", 123.456), IsOk());
  ASSERT_THAT(builder.AddStringClaim("string_claim", "a string"), IsOk());
  ASSERT_THAT(
      builder.AddJsonObjectClaim("object_claim", R"({ "number": 123.456})"),
      IsOk());
  ASSERT_THAT(
      builder.AddJsonArrayClaim("array_claim", R"([1, "one", 1.2, true])"),
      IsOk());

  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.IsNullClaim("null_claim"));
  EXPECT_TRUE(jwt.HasBooleanClaim("boolean_claim"));
  EXPECT_THAT(jwt.GetBooleanClaim("boolean_claim"), IsOkAndHolds(true));
  EXPECT_TRUE(jwt.HasNumberClaim("number_claim"));
  EXPECT_THAT(jwt.GetNumberClaim("number_claim"), IsOkAndHolds(123.456));
  EXPECT_TRUE(jwt.HasStringClaim("string_claim"));
  EXPECT_THAT(jwt.GetStringClaim("string_claim"), IsOkAndHolds("a string"));
  EXPECT_TRUE(jwt.HasJsonObjectClaim("object_claim"));
  EXPECT_THAT(jwt.GetJsonObjectClaim("object_claim"),
              IsOkAndHolds(R"({"number":123.456})"));
  EXPECT_TRUE(jwt.HasJsonArrayClaim("array_claim"));
  EXPECT_THAT(jwt.GetJsonArrayClaim("array_claim"),
              IsOkAndHolds(R"([1,"one",1.2,true])"));

  std::vector<std::string> expected_claim_names = {
      "object_claim", "number_claim", "boolean_claim",
      "array_claim",  "null_claim",   "string_claim"};
  EXPECT_THAT(jwt.CustomClaimNames(),
              UnorderedElementsAreArray(expected_claim_names));
}

TEST(RawJwt, HasCustomClaimIsFalseForWrongType) {
  auto builder = RawJwtBuilder().WithoutExpiration();
  ASSERT_THAT(builder.AddNullClaim("null_claim"), IsOk());
  ASSERT_THAT(builder.AddBooleanClaim("boolean_claim", true), IsOk());
  ASSERT_THAT(builder.AddNumberClaim("number_claim", 123.456), IsOk());
  ASSERT_THAT(builder.AddStringClaim("string_claim", "a string"), IsOk());

  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.IsNullClaim("boolean_claim"));
  EXPECT_FALSE(jwt.HasBooleanClaim("number_claim"));
  EXPECT_FALSE(jwt.HasNumberClaim("string_claim"));
  EXPECT_FALSE(jwt.HasStringClaim("null_claim"));
}

TEST(RawJwt, HasAlwaysReturnsFalseForRegisteredClaims) {
  absl::Time now = absl::Now();
  auto builder =
      RawJwtBuilder().SetIssuer("issuer").SetSubject("subject").SetJwtId(
          "jwt_id");
  ASSERT_THAT(builder.SetNotBefore(now - absl::Seconds(300)), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(now), IsOk());
  ASSERT_THAT(builder.SetExpiration(now + absl::Seconds(300)), IsOk());
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.HasStringClaim("iss"));
  EXPECT_FALSE(jwt.HasStringClaim("sub"));
  EXPECT_FALSE(jwt.HasStringClaim("jti"));
  EXPECT_FALSE(jwt.HasNumberClaim("nbf"));
  EXPECT_FALSE(jwt.HasNumberClaim("iat"));
  EXPECT_FALSE(jwt.HasNumberClaim("exp"));

  EXPECT_THAT(jwt.CustomClaimNames(), IsEmpty());
}

TEST(RawJwt, GetRegisteredCustomClaimNotOK) {
  absl::Time now = absl::Now();
  auto builder =
      RawJwtBuilder().SetIssuer("issuer").SetSubject("subject").SetJwtId(
          "jwt_id");
  ASSERT_THAT(builder.SetNotBefore(now - absl::Seconds(300)), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(now), IsOk());
  ASSERT_THAT(builder.SetExpiration(now + absl::Seconds(300)), IsOk());
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.GetStringClaim("iss").ok());
  EXPECT_FALSE(jwt.GetStringClaim("sub").ok());
  EXPECT_FALSE(jwt.GetStringClaim("jti").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("nbf").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("iat").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("exp").ok());
}

TEST(RawJwt, SetRegisteredCustomClaimNotOK) {
  auto builder = RawJwtBuilder().WithoutExpiration();
  EXPECT_FALSE(builder.AddStringClaim("iss", "issuer").ok());
  EXPECT_FALSE(builder.AddStringClaim("sub", "issuer").ok());
  EXPECT_FALSE(builder.AddStringClaim("jti", "issuer").ok());
  EXPECT_FALSE(builder.AddNumberClaim("nbf", 123).ok());
  EXPECT_FALSE(builder.AddNumberClaim("iat", 123).ok());
  EXPECT_FALSE(builder.AddNumberClaim("exp", 123).ok());
  EXPECT_FALSE(builder.AddBooleanClaim("iss", true).ok());
  EXPECT_FALSE(builder.AddNullClaim("iss").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("iss", "{\"1\": 2}").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("iss", "[1,2]").ok());
}

TEST(RawJwt, SetInvalidJsonObjectClaimNotOK) {
  auto builder = RawJwtBuilder().WithoutExpiration();
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", "invalid").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", R"("string")").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", "42").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", "[1,2]").ok());
}

TEST(RawJwt, SetInvalidJsonArrayClaimNotOK) {
  auto builder = RawJwtBuilder().WithoutExpiration();
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", "invalid").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", R"("string")").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", "42").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", R"({"1": 2})").ok());
}

TEST(RawJwt, EmptyTokenHasAndIsReturnsFalse) {
  auto jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.HasTypeHeader());
  EXPECT_FALSE(jwt.HasIssuer());
  EXPECT_FALSE(jwt.HasSubject());
  EXPECT_FALSE(jwt.HasAudiences());
  EXPECT_FALSE(jwt.HasJwtId());
  EXPECT_FALSE(jwt.HasExpiration());
  EXPECT_FALSE(jwt.HasNotBefore());
  EXPECT_FALSE(jwt.HasIssuedAt());
  EXPECT_FALSE(jwt.IsNullClaim("null_claim"));
  EXPECT_FALSE(jwt.HasBooleanClaim("boolean_claim"));
  EXPECT_FALSE(jwt.HasNumberClaim("number_claim"));
  EXPECT_FALSE(jwt.HasStringClaim("string_claim"));
  EXPECT_FALSE(jwt.HasJsonObjectClaim("object_claim"));
  EXPECT_FALSE(jwt.HasJsonArrayClaim("array_claim"));
}

TEST(RawJwt, EmptyTokenGetReturnsNotOK) {
  auto jwt_or = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.GetTypeHeader().ok());
  EXPECT_FALSE(jwt.GetIssuer().ok());
  EXPECT_FALSE(jwt.GetSubject().ok());
  EXPECT_FALSE(jwt.GetAudiences().ok());
  EXPECT_FALSE(jwt.GetJwtId().ok());
  EXPECT_FALSE(jwt.GetExpiration().ok());
  EXPECT_FALSE(jwt.GetNotBefore().ok());
  EXPECT_FALSE(jwt.GetIssuedAt().ok());
  EXPECT_FALSE(jwt.IsNullClaim("null_claim"));
  EXPECT_FALSE(jwt.GetBooleanClaim("boolean_claim").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("number_claim").ok());
  EXPECT_FALSE(jwt.GetStringClaim("string_claim").ok());
  EXPECT_FALSE(jwt.GetJsonObjectClaim("object_claim").ok());
  EXPECT_FALSE(jwt.GetJsonArrayClaim("array_claim").ok());
}

TEST(RawJwt, BuildCanBeCalledTwice) {
  auto builder = RawJwtBuilder()
                     .SetIssuer("issuer")
                     .SetSubject("subject")
                     .WithoutExpiration();
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  builder.SetSubject("subject2");
  auto jwt2_or = builder.Build();
  ASSERT_THAT(jwt2_or.status(), IsOk());
  auto jwt2 = jwt2_or.ValueOrDie();

  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_THAT(jwt2.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt2.GetSubject(), IsOkAndHolds("subject2"));
}

TEST(RawJwt, FromJson) {
  auto jwt_or = RawJwt::FromJson(
      absl::nullopt,
      R"({"iss":"issuer", "sub":"subject", "exp":123, "aud":["a1", "a2"]})");
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.HasTypeHeader());
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_THAT(jwt.GetExpiration(), IsOkAndHolds(absl::FromUnixSeconds(123)));
  std::vector<std::string> expected_audiences = {"a1", "a2"};
  EXPECT_THAT(jwt.GetAudiences(), IsOkAndHolds(expected_audiences));
}

TEST(RawJwt, FromJsonWithTypeHeader) {
  auto jwt_or = RawJwt::FromJson("typeHeader", R"({"iss":"issuer"})");
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  EXPECT_THAT(jwt.GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
}

TEST(RawJwt, FromJsonExpExpiration) {
  auto jwt_or = RawJwt::FromJson(absl::nullopt, R"({"exp":1e10})");
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  EXPECT_THAT(jwt.GetExpiration(),
              IsOkAndHolds(absl::FromUnixSeconds(10000000000)));
}

TEST(RawJwt, FromJsonExpirationTooLarge) {
  auto jwt_or = RawJwt::FromJson(absl::nullopt, R"({"exp":1e30})");
  EXPECT_FALSE(jwt_or.ok());
}

TEST(RawJwt, FromJsonNegativeExpirationAreInvalid) {
  auto jwt_or = RawJwt::FromJson(absl::nullopt, R"({"exp":-1})");
  EXPECT_FALSE(jwt_or.ok());
}

TEST(RawJwt, FromJsonConvertsStringAudIntoListOfStrings) {
  auto jwt_or = RawJwt::FromJson(absl::nullopt, R"({"aud":"audience"})");
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  std::vector<std::string> expected = {"audience"};
  EXPECT_TRUE(jwt.HasAudiences());
  EXPECT_THAT(jwt.GetAudiences(), IsOkAndHolds(expected));
}

TEST(RawJwt, FromJsonWithBadRegisteredTypes) {
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"iss":123})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"sub":123})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"aud":123})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"aud":[]})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"aud":["abc",123]})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"exp":"abc"})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"nbf":"abc"})").ok());
  EXPECT_FALSE(RawJwt::FromJson(absl::nullopt, R"({"iat":"abc"})").ok());
}

TEST(RawJwt, GetJsonPayload) {
  auto jwt_or = RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  ASSERT_THAT(jwt.GetJsonPayload(), IsOkAndHolds(R"({"iss":"issuer"})"));
}

TEST(RawJwt, GetExpirationJsonPayload) {
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetExpiration(absl::FromUnixSeconds(2218027244)), IsOk());
  util::StatusOr<RawJwt> jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  EXPECT_THAT(jwt.GetJsonPayload(), IsOkAndHolds(R"({"exp":2218027244})"));
}

TEST(RawJwt, GetNanoExpirationJsonPayload) {
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.SetExpiration(absl::FromUnixNanos(123456789012)), IsOk());
  util::StatusOr<RawJwt> jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  EXPECT_THAT(jwt.GetJsonPayload(), IsOkAndHolds(R"({"exp":123})"));
}

}  // namespace tink
}  // namespace crypto
