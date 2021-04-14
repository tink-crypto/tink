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
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::UnorderedElementsAreArray;
using ::testing::IsEmpty;

namespace crypto {
namespace tink {

TEST(RawJwt, GetIssuerSubjectJwtIdOK) {
  auto jwt_or = RawJwtBuilder()
                    .SetIssuer("issuer")
                    .SetSubject("subject")
                    .SetJwtId("jwt_id")
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasIssuer());
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt.HasSubject());
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_TRUE(jwt.HasJwtId());
  EXPECT_THAT(jwt.GetJwtId(), IsOkAndHolds("jwt_id"));
}

TEST(RawJwt, TimestampsOK) {
  absl::Time now = absl::Now();
  auto jwt_or = RawJwtBuilder()
                    .SetNotBefore(now - absl::Seconds(300))
                    .SetIssuedAt(now)
                    .SetExpiration(now + absl::Seconds(300))
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasNotBefore());
  auto nbf_or = jwt.GetNotBefore();
  ASSERT_THAT(nbf_or.status(), IsOk());
  auto nbf = nbf_or.ValueOrDie();
  EXPECT_LT(nbf, now - absl::Seconds(299));
  EXPECT_GT(nbf, now - absl::Seconds(301));

  EXPECT_TRUE(jwt.HasIssuedAt());
  auto iat_or = jwt.GetIssuedAt();
  ASSERT_THAT(iat_or.status(), IsOk());
  auto iat = iat_or.ValueOrDie();
  EXPECT_LT(iat, now + absl::Seconds(1));
  EXPECT_GT(iat, now - absl::Seconds(1));

  EXPECT_TRUE(jwt.HasExpiration());
  auto exp_or = jwt.GetExpiration();
  ASSERT_THAT(exp_or.status(), IsOk());
  auto exp = exp_or.ValueOrDie();
  EXPECT_LT(exp, now + absl::Seconds(301));
  EXPECT_GT(exp, now + absl::Seconds(299));
}

TEST(RawJwt, AddGetAudiencesOK) {
  auto jwt_or = RawJwtBuilder()
                    .AddAudience("audience1")
                    .AddAudience("audience2")
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  std::vector<std::string> expected = {"audience1", "audience2"};
  EXPECT_TRUE(jwt.HasAudiences());
  EXPECT_THAT(jwt.GetAudiences(), IsOkAndHolds(expected));
}

TEST(RawJwt, GetCustomClaimOK) {
  auto builder = RawJwtBuilder();
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
  auto builder = RawJwtBuilder();
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
  auto jwt_or = RawJwtBuilder()
                    .SetIssuer("issuer")
                    .SetSubject("subject")
                    .SetJwtId("jwt_id")
                    .SetNotBefore(now - absl::Seconds(300))
                    .SetIssuedAt(now)
                    .SetExpiration(now + absl::Seconds(300))
                    .Build();
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
  auto jwt_or = RawJwtBuilder()
                    .SetIssuer("issuer")
                    .SetSubject("subject")
                    .SetJwtId("jwt_id")
                    .SetNotBefore(now - absl::Seconds(300))
                    .SetIssuedAt(now)
                    .SetExpiration(now + absl::Seconds(300))
                    .Build();
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
  auto builder = RawJwtBuilder();
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
  auto builder = RawJwtBuilder();
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", "invalid").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", R"("string")").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", "42").ok());
  EXPECT_FALSE(builder.AddJsonObjectClaim("obj", "[1,2]").ok());
}

TEST(RawJwt, SetInvalidJsonArrayClaimNotOK) {
  auto builder = RawJwtBuilder();
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", "invalid").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", R"("string")").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", "42").ok());
  EXPECT_FALSE(builder.AddJsonArrayClaim("arr", R"({"1": 2})").ok());
}

TEST(RawJwt, EmptyTokenHasAndIsReturnsFalse) {
  auto jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

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
  auto jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

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
  auto builder = RawJwtBuilder().SetIssuer("issuer").SetSubject("subject");
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

TEST(RawJwt, FromString) {
  auto jwt_or =
      RawJwt::FromString(R"({"iss":"issuer", "sub":"subject", "exp":123})");
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  ASSERT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  ASSERT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  ASSERT_THAT(jwt.GetExpiration(), IsOkAndHolds(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, ToString) {
  auto jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  ASSERT_THAT(jwt.ToString(), IsOkAndHolds(R"({"iss":"issuer"})"));
}

}  // namespace tink
}  // namespace crypto
