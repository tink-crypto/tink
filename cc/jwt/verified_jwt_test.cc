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

#include "tink/jwt/verified_jwt.h"

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/jwt/internal/jwt_mac_impl.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;

namespace crypto {
namespace tink {

namespace {

util::StatusOr<VerifiedJwt> CreateVerifiedJwt(const RawJwt& raw_jwt) {
  // Creating a VerifiedJwt is a bit complicated since it can only be created
  // JWT primitives.
  std::string key_value;
  if (!absl::WebSafeBase64Unescape(
          "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1"
          "qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          &key_value)) {
    return util::Status(util::error::INVALID_ARGUMENT, "failed to parse key");
  }
  crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac_or =
      subtle::HmacBoringSsl::New(
          util::Enums::ProtoToSubtle(google::crypto::tink::HashType::SHA256),
          32, util::SecretDataFromStringView(key_value));
  if (!mac_or.ok()) {
    return mac_or.status();
  }
  std::unique_ptr<jwt_internal::JwtMacInternal> jwt_mac =
      absl::make_unique<jwt_internal::JwtMacImpl>(
          std::move(mac_or.ValueOrDie()), "HS256");

  auto compact_or = jwt_mac->ComputeMacAndEncodeWithKid(raw_jwt, "kid-123");
  if (!compact_or.ok()) {
    return compact_or.status();
  }
  auto validator_builder = JwtValidatorBuilder();
  auto issued_at_or = raw_jwt.GetIssuedAt();
  if (issued_at_or.ok()) {
    validator_builder.SetFixedNow(issued_at_or.ValueOrDie());
  }
  auto audience_or = raw_jwt.GetAudiences();
  if (audience_or.ok()) {
    validator_builder.SetAudience(audience_or.ValueOrDie()[0]);
  }
  return jwt_mac->VerifyMacAndDecode(compact_or.ValueOrDie(),
                                     validator_builder.Build());
}

TEST(VerifiedJwt, GetTypeIssuerSubjectJwtIdOK) {
  auto raw_jwt_or = RawJwtBuilder()
                        .SetTypeHeader("typeHeader")
                        .SetIssuer("issuer")
                        .SetSubject("subject")
                        .SetJwtId("jwt_id")
                        .Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasTypeHeader());
  EXPECT_THAT(jwt.GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_TRUE(jwt.HasIssuer());
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt.HasSubject());
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_TRUE(jwt.HasJwtId());
  EXPECT_THAT(jwt.GetJwtId(), IsOkAndHolds("jwt_id"));
}

TEST(VerifiedJwt, TimestampsOK) {
  absl::Time now = absl::Now();
  auto builder = RawJwtBuilder().SetIssuer("issuer");
  ASSERT_THAT(builder.SetNotBefore(now - absl::Seconds(300)), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(now), IsOk());
  ASSERT_THAT(builder.SetExpiration(now + absl::Seconds(300)), IsOk());
  auto raw_jwt_or = builder.Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

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

TEST(VerifiedJwt, GetAudiencesOK) {
  auto raw_jwt_or =
      RawJwtBuilder().AddAudience("audience1").AddAudience("audience2").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

  std::vector<std::string> expected = {"audience1", "audience2"};
  EXPECT_TRUE(jwt.HasAudiences());
  EXPECT_THAT(jwt.GetAudiences(), IsOkAndHolds(expected));
}

TEST(VerifiedJwt, GetCustomClaimOK) {
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

  auto raw_jwt_or = builder.Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

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
              testing::UnorderedElementsAreArray(expected_claim_names));
}

TEST(VerifiedJwt, HasCustomClaimIsFalseForWrongType) {
  auto builder = RawJwtBuilder();
  ASSERT_THAT(builder.AddNullClaim("null_claim"), IsOk());
  ASSERT_THAT(builder.AddBooleanClaim("boolean_claim", true), IsOk());
  ASSERT_THAT(builder.AddNumberClaim("number_claim", 123.456), IsOk());
  ASSERT_THAT(builder.AddStringClaim("string_claim", "a string"), IsOk());

  auto raw_jwt_or = builder.Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.IsNullClaim("boolean_claim"));
  EXPECT_FALSE(jwt.HasBooleanClaim("number_claim"));
  EXPECT_FALSE(jwt.HasNumberClaim("string_claim"));
  EXPECT_FALSE(jwt.HasStringClaim("null_claim"));
}

TEST(VerifiedJwt, HasAlwaysReturnsFalseForRegisteredClaims) {
  absl::Time now = absl::Now();
  auto builder = RawJwtBuilder()
                        .SetIssuer("issuer")
                        .SetSubject("subject")
                        .SetJwtId("jwt_id");
  ASSERT_THAT(builder.SetNotBefore(now - absl::Seconds(300)), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(now), IsOk());
  ASSERT_THAT(builder.SetExpiration(now + absl::Seconds(300)), IsOk());
  auto raw_jwt_or = builder.Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.HasStringClaim("iss"));
  EXPECT_FALSE(jwt.HasStringClaim("sub"));
  EXPECT_FALSE(jwt.HasStringClaim("jti"));
  EXPECT_FALSE(jwt.HasNumberClaim("nbf"));
  EXPECT_FALSE(jwt.HasNumberClaim("iat"));
  EXPECT_FALSE(jwt.HasNumberClaim("exp"));

  EXPECT_THAT(jwt.CustomClaimNames(), testing::IsEmpty());
}

TEST(VerifiedJwt, GetRegisteredCustomClaimNotOK) {
  absl::Time now = absl::Now();
  auto builder =
      RawJwtBuilder().SetIssuer("issuer").SetSubject("subject").SetJwtId(
          "jwt_id");
  ASSERT_THAT(builder.SetNotBefore(now - absl::Seconds(300)), IsOk());
  ASSERT_THAT(builder.SetIssuedAt(now), IsOk());
  ASSERT_THAT(builder.SetExpiration(now + absl::Seconds(300)), IsOk());
  auto raw_jwt_or = builder.Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.GetStringClaim("iss").ok());
  EXPECT_FALSE(jwt.GetStringClaim("sub").ok());
  EXPECT_FALSE(jwt.GetStringClaim("jti").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("nbf").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("iat").ok());
  EXPECT_FALSE(jwt.GetNumberClaim("exp").ok());
}

TEST(VerifiedJwt, EmptyTokenHasAndIsReturnsFalse) {
  auto raw_jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

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

TEST(VerifiedJwt, EmptyTokenGetReturnsNotOK) {
  auto raw_jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

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

TEST(VerifiedJwt, GetJsonPayload) {
  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();

  EXPECT_THAT(jwt.GetJsonPayload(), IsOkAndHolds(R"({"iss":"issuer"})"));
}

TEST(VerifiedJwt, MoveMakesCopy) {
  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto verified_jwt_or = CreateVerifiedJwt(raw_jwt_or.ValueOrDie());
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  VerifiedJwt jwt = verified_jwt_or.ValueOrDie();
  VerifiedJwt jwt2 = std::move(jwt);
  EXPECT_TRUE(jwt.HasIssuer());
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt2.HasIssuer());
  EXPECT_THAT(jwt2.GetIssuer(), IsOkAndHolds("issuer"));
}

}  // namespace

}  // namespace tink
}  // namespace crypto
