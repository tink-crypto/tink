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

#include <string>
#include <utility>

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
  crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac =
      subtle::HmacBoringSsl::New(
          util::Enums::ProtoToSubtle(google::crypto::tink::HashType::SHA256),
          32, util::SecretDataFromStringView(key_value));
  if (!mac.ok()) {
    return mac.status();
  }
  std::unique_ptr<jwt_internal::JwtMacInternal> jwt_mac =
      absl::make_unique<jwt_internal::JwtMacImpl>(std::move(*mac), "HS256",
                                                  absl::nullopt);

  util::StatusOr<std::string> compact =
      jwt_mac->ComputeMacAndEncodeWithKid(raw_jwt, "kid-123");
  if (!compact.ok()) {
    return compact.status();
  }
  JwtValidatorBuilder validator_builder = JwtValidatorBuilder()
                                              .IgnoreTypeHeader()
                                              .IgnoreIssuer()
                                              .IgnoreSubject()
                                              .IgnoreAudiences()
                                              .AllowMissingExpiration();
  util::StatusOr<absl::Time> issued_at = raw_jwt.GetIssuedAt();
  if (issued_at.ok()) {
    validator_builder.SetFixedNow(*issued_at);
  }
  util::StatusOr<JwtValidator> validator = validator_builder.Build();
  if (!validator.ok()) {
    return validator.status();
  }
  return jwt_mac->VerifyMacAndDecode(*compact, *validator);
}

TEST(VerifiedJwt, GetTypeIssuerSubjectJwtIdOK) {
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                          .SetTypeHeader("typeHeader")
                                          .SetIssuer("issuer")
                                          .SetSubject("subject")
                                          .SetJwtId("jwt_id")
                                          .WithoutExpiration()
                                          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<crypto::tink::VerifiedJwt> jwt =
      CreateVerifiedJwt(*raw_jwt);
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

TEST(VerifiedJwt, TimestampsOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .SetIssuer("issuer")
          .SetNotBefore(now - absl::Seconds(300))
          .SetIssuedAt(now)
          .SetExpiration(now + absl::Seconds(300))
          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<crypto::tink::VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_TRUE(jwt->HasNotBefore());
  util::StatusOr<absl::Time> nbf = jwt->GetNotBefore();
  ASSERT_THAT(nbf.status(), IsOk());
  EXPECT_LT(*nbf, now - absl::Seconds(299));
  EXPECT_GT(*nbf, now - absl::Seconds(301));

  EXPECT_TRUE(jwt->HasIssuedAt());
  util::StatusOr<absl::Time> iat = jwt->GetIssuedAt();
  ASSERT_THAT(iat.status(), IsOk());
  EXPECT_LT(*iat, now + absl::Seconds(1));
  EXPECT_GT(*iat, now - absl::Seconds(1));

  EXPECT_TRUE(jwt->HasExpiration());
  util::StatusOr<absl::Time> exp = jwt->GetExpiration();
  ASSERT_THAT(exp.status(), IsOk());
  EXPECT_LT(*exp, now + absl::Seconds(301));
  EXPECT_GT(*exp, now + absl::Seconds(299));
}

TEST(VerifiedJwt, GetAudiencesOK) {
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                          .AddAudience("audience1")
                                          .AddAudience("audience2")
                                          .WithoutExpiration()
                                          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());

  std::vector<std::string> expected = {"audience1", "audience2"};
  EXPECT_TRUE(jwt->HasAudiences());
  EXPECT_THAT(jwt->GetAudiences(), IsOkAndHolds(expected));
}

TEST(VerifiedJwt, GetCustomClaimOK) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .WithoutExpiration()
          .AddNullClaim("null_claim")
          .AddBooleanClaim("boolean_claim", true)
          .AddNumberClaim("number_claim", 123.456)
          .AddStringClaim("string_claim", "a string")
          .AddJsonObjectClaim("object_claim", R"({ "number": 123.456})")
          .AddJsonArrayClaim("array_claim", R"([1, "one", 1.2, true])")
          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
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
              testing::UnorderedElementsAreArray(expected_claim_names));
}

TEST(VerifiedJwt, HasCustomClaimIsFalseForWrongType) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .WithoutExpiration()
          .AddNullClaim("null_claim")
          .AddBooleanClaim("boolean_claim", true)
          .AddNumberClaim("number_claim", 123.456)
          .AddStringClaim("string_claim", "a string")
          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->IsNullClaim("boolean_claim"));
  EXPECT_FALSE(jwt->HasBooleanClaim("number_claim"));
  EXPECT_FALSE(jwt->HasNumberClaim("string_claim"));
  EXPECT_FALSE(jwt->HasStringClaim("null_claim"));
}

TEST(VerifiedJwt, HasAlwaysReturnsFalseForRegisteredClaims) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .SetIssuer("issuer")
          .SetSubject("subject")
          .SetJwtId("jwt_id")
          .SetNotBefore(now - absl::Seconds(300))
          .SetIssuedAt(now)
          .SetExpiration(now + absl::Seconds(300))
          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->HasStringClaim("iss"));
  EXPECT_FALSE(jwt->HasStringClaim("sub"));
  EXPECT_FALSE(jwt->HasStringClaim("jti"));
  EXPECT_FALSE(jwt->HasNumberClaim("nbf"));
  EXPECT_FALSE(jwt->HasNumberClaim("iat"));
  EXPECT_FALSE(jwt->HasNumberClaim("exp"));

  EXPECT_THAT(jwt->CustomClaimNames(), testing::IsEmpty());
}

TEST(VerifiedJwt, GetRegisteredCustomClaimNotOK) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder()
          .SetIssuer("issuer")
          .SetSubject("subject")
          .SetJwtId("jwt_id")
          .SetNotBefore(now - absl::Seconds(300))
          .SetIssuedAt(now)
          .SetExpiration(now + absl::Seconds(300))
          .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->GetStringClaim("iss").ok());
  EXPECT_FALSE(jwt->GetStringClaim("sub").ok());
  EXPECT_FALSE(jwt->GetStringClaim("jti").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("nbf").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("iat").ok());
  EXPECT_FALSE(jwt->GetNumberClaim("exp").ok());
}

TEST(VerifiedJwt, EmptyTokenHasAndIsReturnsFalse) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
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

TEST(VerifiedJwt, EmptyTokenGetReturnsNotOK) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
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

TEST(VerifiedJwt, GetJsonPayload) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_THAT(jwt->GetJsonPayload(), IsOkAndHolds(R"({"iss":"issuer"})"));
}

TEST(VerifiedJwt, MoveMakesCopy) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  util::StatusOr<VerifiedJwt> jwt = CreateVerifiedJwt(*raw_jwt);
  ASSERT_THAT(jwt.status(), IsOk());
  VerifiedJwt jwt1 = *jwt;
  VerifiedJwt jwt2 = std::move(jwt1);
  // We want that a VerifiedJwt object remains a valid object, even after
  // std::moved has been called.
  EXPECT_TRUE(jwt1.HasIssuer());
  EXPECT_THAT(jwt1.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt2.HasIssuer());
  EXPECT_THAT(jwt2.GetIssuer(), IsOkAndHolds("issuer"));
}

}  // namespace

}  // namespace tink
}  // namespace crypto
