// Copyright 2021 Google LLC.
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

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/util/test_matchers.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::Not;

namespace crypto {
namespace tink {
namespace jwt_internal {

namespace {

class JwtSignatureImplTest : public ::testing::Test {
 protected:
  void SetUp() override {
    util::StatusOr<crypto::tink::subtle::SubtleUtilBoringSSL::EcKey> ec_key =
        subtle::SubtleUtilBoringSSL::GetNewEcKey(
            subtle::EllipticCurveType::NIST_P256);
    ASSERT_THAT(ec_key.status(), IsOk());

    util::StatusOr<std::unique_ptr<subtle::EcdsaSignBoringSsl>> sign =
        subtle::EcdsaSignBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(sign.status(), IsOk());

    util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>> verify =
        subtle::EcdsaVerifyBoringSsl::New(
            *ec_key, subtle::HashType::SHA256,
            subtle::EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_THAT(verify.status(), IsOk());

    jwt_sign_ = absl::make_unique<JwtPublicKeySignImpl>(
        *std::move(sign), "ES256", /*custom_kid=*/absl::nullopt);
    jwt_verify_ = absl::make_unique<JwtPublicKeyVerifyImpl>(
        *std::move(verify), "ES256", /*custom_kid=*/absl::nullopt);
  }
  std::unique_ptr<JwtPublicKeySignImpl> jwt_sign_;
  std::unique_ptr<JwtPublicKeyVerifyImpl> jwt_verify_;
};

TEST_F(JwtSignatureImplTest, CreateAndValidateToken) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt_or =
      RawJwtBuilder()
          .SetTypeHeader("typeHeader")
          .SetJwtId("id123")
          .SetNotBefore(now - absl::Seconds(300))
          .SetIssuedAt(now)
          .SetExpiration(now + absl::Seconds(300))
          .Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact =
      jwt_sign_->SignAndEncodeWithKid(raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator.status(), IsOk());

  // Success
  util::StatusOr<VerifiedJwt> verified_jwt =
      jwt_verify_->VerifyAndDecodeWithKid(*compact, *validator,
                                          /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  // Fails because kid header is not present
  EXPECT_THAT(
      jwt_verify_->VerifyAndDecodeWithKid(*compact, *validator, "kid-123")
          .status(),
      Not(IsOk()));

  // Fails with wrong issuer
  util::StatusOr<JwtValidator> validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build();
  ASSERT_THAT(validator2.status(), IsOk());
  EXPECT_FALSE(
      jwt_verify_
          ->VerifyAndDecodeWithKid(*compact, *validator2, /*kid=*/absl::nullopt)
          .ok());

  // Fails because token is not yet valid
  util::StatusOr<JwtValidator> validator_1970 =
      JwtValidatorBuilder().SetFixedNow(absl::FromUnixSeconds(12345)).Build();
  ASSERT_THAT(validator_1970.status(), IsOk());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid(*compact, *validator_1970,
                                            /*kid=*/absl::nullopt)
                   .ok());
}

TEST_F(JwtSignatureImplTest, CreateAndValidateTokenWithKid) {
  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      jwt_sign_->SignAndEncodeWithKid(*raw_jwt, "kid-123");
  ASSERT_THAT(compact.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();

  util::StatusOr<VerifiedJwt> verified_jwt =
      jwt_verify_->VerifyAndDecodeWithKid(*compact, *validator, "kid-123");
  ASSERT_THAT(verified_jwt.status(), IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  // Kid header in the token is ignored.
  EXPECT_THAT(
      jwt_verify_
          ->VerifyAndDecodeWithKid(*compact, *validator, /*kid=*/absl::nullopt)
          .status(),
      IsOk());

  // parse header to make sure the kid value is set correctly.
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header.status(), IsOk());
  EXPECT_THAT(header->fields().find("kid")->second.string_value(),
              Eq("kid-123"));
}

TEST_F(JwtSignatureImplTest, FailsWithModifiedCompact) {
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetJwtId("id123").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      jwt_sign_->SignAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());
  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());

  EXPECT_THAT(
      jwt_verify_
          ->VerifyAndDecodeWithKid(*compact, *validator, /*kid=*/absl::nullopt)
          .status(),
      IsOk());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid(absl::StrCat(*compact, "x"),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid(absl::StrCat(*compact, " "),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid(absl::StrCat("x", *compact),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid(absl::StrCat(" ", *compact),
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
}

TEST_F(JwtSignatureImplTest, FailsWithInvalidTokens) {
  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  ASSERT_THAT(validator.status(), IsOk());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.YWJj.",
                                            *validator, /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9?.e30.YWJj",
                                            *validator, /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30?.YWJj",
                                            *validator, /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.YWJj?",
                                            *validator, /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(jwt_verify_
                   ->VerifyAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.YWJj",
                                            *validator,
                                            /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE(
      jwt_verify_->VerifyAndDecodeWithKid("", *validator, /*kid=*/absl::nullopt)
          .ok());
  EXPECT_FALSE(
      jwt_verify_
          ->VerifyAndDecodeWithKid("..", *validator, /*kid=*/absl::nullopt)

          .ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
