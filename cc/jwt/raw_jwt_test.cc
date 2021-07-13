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

#include <string>

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/time/time.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::IsEmpty;
using ::testing::UnorderedElementsAreArray;

namespace crypto {
namespace tink {

TEST(RawJwt, GetTypeHeaderIssuerSubjectJwtIdOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetTypeHeader("typeHeader")
                                   .SetIssuer("issuer")
                                   .SetSubject("subject")
                                   .SetJwtId("jwt_id")
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasTypeHeader());
  EXPECT_THAT(jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_TRUE(jwt->HasIssuer());
  EXPECT_THAT(jwt->GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt->HasSubject());
  EXPECT_THAT(jwt->GetSubject(), IsOkAndHolds("subject"));
  EXPECT_TRUE(jwt->HasJwtId());
  EXPECT_THAT(jwt->GetJwtId(), IsOkAndHolds("jwt_id"));
}

TEST(RawJwt, TimestampsOK) {
  absl::Time nbf = absl::FromUnixSeconds(1234567890);
  absl::Time iat = absl::FromUnixSeconds(1234567891);
  absl::Time exp = absl::FromUnixSeconds(1234567892);
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(nbf)
                                   .SetIssuedAt(iat)
                                   .SetExpiration(exp)
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasNotBefore());
  EXPECT_THAT(jwt->GetNotBefore(), IsOkAndHolds(nbf));

  EXPECT_TRUE(jwt->HasIssuedAt());
  EXPECT_THAT(jwt->GetIssuedAt(), IsOkAndHolds(iat));

  EXPECT_TRUE(jwt->HasExpiration());
  EXPECT_THAT(jwt->GetExpiration(), IsOkAndHolds(exp));
}

TEST(RawJwt, ExpWithMillisAlwaysRoundDown) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(absl::FromUnixMillis(123999)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasExpiration());
  util::StatusOr<absl::Time> exp = jwt->GetExpiration();
  EXPECT_THAT(exp, IsOkAndHolds(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, NbfWithMillisAlwaysRoundDown) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(absl::FromUnixMillis(123999))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasNotBefore());
  util::StatusOr<absl::Time> nbf = jwt->GetNotBefore();
  EXPECT_THAT(nbf, IsOkAndHolds(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, IatWithMillisAlwaysRoundDown) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetIssuedAt(absl::FromUnixMillis(123999))
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasIssuedAt());
  util::StatusOr<absl::Time> iat = jwt->GetIssuedAt();
  EXPECT_THAT(iat, IsOkAndHolds(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, LargeExpirationWorks) {
  absl::Time large = absl::FromUnixSeconds(253402300799);  // year 9999
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetNotBefore(large)
                                   .SetIssuedAt(large)
                                   .SetExpiration(large)
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasExpiration());
  EXPECT_TRUE(jwt->HasIssuedAt());
  EXPECT_TRUE(jwt->HasNotBefore());
  util::StatusOr<absl::Time> exp = jwt->GetExpiration();
  EXPECT_THAT(exp, IsOkAndHolds(large));
  util::StatusOr<absl::Time> iat = jwt->GetIssuedAt();
  EXPECT_THAT(iat, IsOkAndHolds(large));
  util::StatusOr<absl::Time> nbf = jwt->GetNotBefore();
  EXPECT_THAT(nbf, IsOkAndHolds(large));
}

TEST(RawJwt, TooLargeTimestampsFail) {
  absl::Time too_large = absl::FromUnixSeconds(253402300800);  // year 10000
  EXPECT_FALSE(RawJwtBuilder().SetExpiration(too_large).Build().ok());
  EXPECT_FALSE(
      RawJwtBuilder().SetIssuedAt(too_large).WithoutExpiration().Build().ok());
  EXPECT_FALSE(
      RawJwtBuilder().SetNotBefore(too_large).WithoutExpiration().Build().ok());
}

TEST(RawJwt, NegativeTimestampsFail) {
  absl::Time neg = absl::FromUnixMillis(-1);
  EXPECT_FALSE(RawJwtBuilder().SetExpiration(neg).Build().ok());
  EXPECT_FALSE(
      RawJwtBuilder().SetIssuedAt(neg).WithoutExpiration().Build().ok());
  EXPECT_FALSE(
      RawJwtBuilder().SetNotBefore(neg).WithoutExpiration().Build().ok());
}

TEST(RawJwt, SetExpirationAndWithoutExpirationFail) {
  absl::Time exp = absl::FromUnixMillis(12345);
  EXPECT_FALSE(
      RawJwtBuilder().SetExpiration(exp).WithoutExpiration().Build().ok());
}

TEST(RawJwt, NeitherSetExpirationNorWithoutExpirationFail) {
  EXPECT_FALSE(RawJwtBuilder().Build().ok());
}

TEST(RawJwt, AddGetAudiencesOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .AddAudience("audience1")
                                   .AddAudience("audience2")
                                   .WithoutExpiration()
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  std::vector<std::string> expected = {"audience1", "audience2"};
  EXPECT_TRUE(jwt->HasAudiences());
  EXPECT_THAT(jwt->GetAudiences(), IsOkAndHolds(expected));
}

TEST(RawJwt, GetCustomClaimOK) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder()
          .WithoutExpiration()
          .AddNullClaim("null_claim")
          .AddBooleanClaim("boolean_claim", true)
          .AddNumberClaim("number_claim", 123.456)
          .AddStringClaim("string_claim", "a string")
          .AddJsonObjectClaim("object_claim", R"({ "number": 123.456})")
          .AddJsonArrayClaim("array_claim", R"([1, "one", 1.2, true])")
          .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->IsNullClaim("null_claim"));
  EXPECT_TRUE(jwt->HasBooleanClaim("boolean_claim"));
  EXPECT_THAT(jwt->GetBooleanClaim("boolean_claim"), IsOkAndHolds(true));
  EXPECT_TRUE(jwt->HasNumberClaim("number_claim"));
  EXPECT_THAT(jwt->GetNumberClaim("number_claim"), IsOkAndHolds(123.456));
  EXPECT_TRUE(jwt->HasStringClaim("string_claim"));
  EXPECT_THAT(jwt->GetStringClaim("string_claim"), IsOkAndHolds("a string"));
  EXPECT_TRUE(jwt->HasJsonObjectClaim("object_claim"));
  EXPECT_THAT(jwt->GetJsonObjectClaim("object_claim"),
              IsOkAndHolds(R"({"number":123.456})"));
  EXPECT_TRUE(jwt->HasJsonArrayClaim("array_claim"));
  EXPECT_THAT(jwt->GetJsonArrayClaim("array_claim"),
              IsOkAndHolds(R"([1,"one",1.2,true])"));

  std::vector<std::string> expected_claim_names = {
      "object_claim", "number_claim", "boolean_claim",
      "array_claim",  "null_claim",   "string_claim"};
  EXPECT_THAT(jwt->CustomClaimNames(),
              UnorderedElementsAreArray(expected_claim_names));
}

TEST(RawJwt, HasCustomClaimIsFalseForWrongType) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .WithoutExpiration()
                                   .AddNullClaim("null_claim")
                                   .AddBooleanClaim("boolean_claim", true)
                                   .AddNumberClaim("number_claim", 123.456)
                                   .AddStringClaim("string_claim", "a string")
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->IsNullClaim("boolean_claim"));
  EXPECT_FALSE(jwt->HasBooleanClaim("number_claim"));
  EXPECT_FALSE(jwt->HasNumberClaim("string_claim"));
  EXPECT_FALSE(jwt->HasStringClaim("null_claim"));
}

TEST(RawJwt, HasAlwaysReturnsFalseForRegisteredClaims) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetIssuer("issuer")
                                   .SetSubject("subject")
                                   .SetJwtId("jwt_id")
                                   .SetNotBefore(now - absl::Seconds(300))
                                   .SetIssuedAt(now)
                                   .SetExpiration(now + absl::Seconds(300))
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->HasStringClaim("iss"));
  EXPECT_FALSE(jwt->HasStringClaim("sub"));
  EXPECT_FALSE(jwt->HasStringClaim("jti"));
  EXPECT_FALSE(jwt->HasNumberClaim("nbf"));
  EXPECT_FALSE(jwt->HasNumberClaim("iat"));
  EXPECT_FALSE(jwt->HasNumberClaim("exp"));

  EXPECT_THAT(jwt->CustomClaimNames(), IsEmpty());
}

TEST(RawJwt, GetRegisteredCustomClaimNotOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> jwt = RawJwtBuilder()
                                   .SetIssuer("issuer")
                                   .SetSubject("subject")
                                   .SetJwtId("jwt_id")
                                   .SetNotBefore(now - absl::Seconds(300))
                                   .SetIssuedAt(now)
                                   .SetExpiration(now + absl::Seconds(300))
                                   .Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->GetStringClaim("iss").ok());
  EXPECT_FALSE(jwt->GetStringClaim("sub").ok());
  EXPECT_FALSE(jwt->GetStringClaim("jti").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("nbf").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("iat").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("exp").ok());
}

TEST(RawJwt, SetRegisteredCustomClaimNotOK) {
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddStringClaim("iss", "issuer")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddStringClaim("sub", "issuer")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddStringClaim("jti", "issuer")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddNumberClaim("nbf", 123)
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddNumberClaim("iat", 123)
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddNumberClaim("exp", 123)
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddBooleanClaim("iss", true)
                   .Build()
                   .ok());
  EXPECT_FALSE(
      RawJwtBuilder().WithoutExpiration().AddNullClaim("iss").Build().ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonObjectClaim("iss", "{\"1\": 2}")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonArrayClaim("iss", "[1,2]")
                   .Build()
                   .ok());
}

TEST(RawJwt, SetInvalidJsonObjectClaimNotOK) {
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonObjectClaim("obj", "invalid")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonObjectClaim("obj", R"("string")")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonObjectClaim("obj", "42")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonObjectClaim("obj", "[1,2]")
                   .Build()
                   .ok());
}

TEST(RawJwt, SetInvalidJsonArrayClaimNotOK) {
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonArrayClaim("arr", "invalid")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonArrayClaim("arr", R"("string")")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonArrayClaim("arr", "42")
                   .Build()
                   .ok());
  EXPECT_FALSE(RawJwtBuilder()
                   .WithoutExpiration()
                   .AddJsonArrayClaim("arr", R"({"1": 2})")
                   .Build()
                   .ok());
}

TEST(RawJwt, EmptyTokenHasAndIsReturnsFalse) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->HasTypeHeader());
  EXPECT_FALSE(jwt->HasIssuer());
  EXPECT_FALSE(jwt->HasSubject());
  EXPECT_FALSE(jwt->HasAudiences());
  EXPECT_FALSE(jwt->HasJwtId());
  EXPECT_FALSE(jwt->HasExpiration());
  EXPECT_FALSE(jwt->HasNotBefore());
  EXPECT_FALSE(jwt->HasIssuedAt());
  EXPECT_FALSE(jwt->IsNullClaim("null_claim"));
  EXPECT_FALSE(jwt->HasBooleanClaim("boolean_claim"));
  EXPECT_FALSE(jwt->HasNumberClaim("number_claim"));
  EXPECT_FALSE(jwt->HasStringClaim("string_claim"));
  EXPECT_FALSE(jwt->HasJsonObjectClaim("object_claim"));
  EXPECT_FALSE(jwt->HasJsonArrayClaim("array_claim"));
}

TEST(RawJwt, EmptyTokenGetReturnsNotOK) {
  util::StatusOr<RawJwt> jwt = RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->GetTypeHeader().ok());
  EXPECT_FALSE(jwt->GetIssuer().ok());
  EXPECT_FALSE(jwt->GetSubject().ok());
  EXPECT_FALSE(jwt->GetAudiences().ok());
  EXPECT_FALSE(jwt->GetJwtId().ok());
  EXPECT_FALSE(jwt->GetExpiration().ok());
  EXPECT_FALSE(jwt->GetNotBefore().ok());
  EXPECT_FALSE(jwt->GetIssuedAt().ok());
  EXPECT_FALSE(jwt->IsNullClaim("null_claim"));
  EXPECT_FALSE(jwt->GetBooleanClaim("boolean_claim").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("number_claim").ok());
  EXPECT_FALSE(jwt->GetStringClaim("string_claim").ok());
  EXPECT_FALSE(jwt->GetJsonObjectClaim("object_claim").ok());
  EXPECT_FALSE(jwt->GetJsonArrayClaim("array_claim").ok());
}

TEST(RawJwt, BuildCanBeCalledTwice) {
  auto builder = RawJwtBuilder()
                     .SetIssuer("issuer")
                     .SetSubject("subject")
                     .WithoutExpiration();
  util::StatusOr<RawJwt> jwt = builder.Build();
  ASSERT_THAT(jwt.status(), IsOk());

  builder.SetSubject("subject2");
  util::StatusOr<RawJwt> jwt2 = builder.Build();
  ASSERT_THAT(jwt2.status(), IsOk());

  EXPECT_THAT(jwt->GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt->GetSubject(), IsOkAndHolds("subject"));
  EXPECT_THAT(jwt2->GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt2->GetSubject(), IsOkAndHolds("subject2"));
}

TEST(RawJwt, GetJsonPayload) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(jwt.status(), IsOk());

  ASSERT_THAT(jwt->GetJsonPayload(), IsOkAndHolds(R"({"iss":"issuer"})"));
}

TEST(RawJwt, GetExpirationJsonPayload) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(absl::FromUnixSeconds(2218027244)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_THAT(jwt->GetJsonPayload(), IsOkAndHolds(R"({"exp":2218027244})"));
}

TEST(RawJwt, GetNanoExpirationJsonPayload) {
  util::StatusOr<RawJwt> jwt =
      RawJwtBuilder().SetExpiration(absl::FromUnixNanos(123456789012)).Build();
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_THAT(jwt->GetJsonPayload(), IsOkAndHolds(R"({"exp":123})"));
}

}  // namespace tink
}  // namespace crypto
