// Copyright 2021 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtEcdsaPrivateKey;
using ::google::crypto::tink::JwtEcdsaPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(JwtEcdsaSignVerifyKeyManagerTest, BasicsSign) {
  EXPECT_EQ(JwtEcdsaSignKeyManager().get_version(), 0);
  EXPECT_EQ(JwtEcdsaSignKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey");
  EXPECT_EQ(JwtEcdsaSignKeyManager().key_material_type(),
            google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE);
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, BasicsVerify) {
  EXPECT_EQ(JwtEcdsaVerifyKeyManager().get_version(), 0);
  EXPECT_EQ(JwtEcdsaVerifyKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey");
  EXPECT_EQ(JwtEcdsaVerifyKeyManager().key_material_type(),
            google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC);
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, ValidateEmptyPrivateKey) {
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKey(JwtEcdsaPrivateKey()),
              Not(IsOk()));
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, ValidateEmptyPublicKey) {
  EXPECT_THAT(JwtEcdsaVerifyKeyManager().ValidateKey(JwtEcdsaPublicKey()),
              Not(IsOk()));
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKeyFormat(JwtEcdsaKeyFormat()),
              Not(IsOk()));
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, ValidKeyFormatES256) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, ValidateKeyFormatES384) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES384);
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, ValidateKeyFormatES512) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES512);
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, CreatePrivateKeyAndValidate) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  auto key_or = JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  auto key = key_or.ValueOrDie();
  EXPECT_EQ(key.version(), 0);
  EXPECT_EQ(key.public_key().algorithm(), key_format.algorithm());
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKey(key), IsOk());

  // Change key to an invalid algorithm.
  key.mutable_public_key()->set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_FALSE(JwtEcdsaSignKeyManager().ValidateKey(key).ok());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, CreatePublicKeyAndValidate) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  auto key_or = JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  auto public_key_or = JwtEcdsaSignKeyManager().GetPublicKey(
      key_or.ValueOrDie());
  auto public_key = public_key_or.ValueOrDie();
  EXPECT_THAT(JwtEcdsaVerifyKeyManager().ValidateKey(public_key),
              IsOk());

  // Change key to an invalid algorithm.
  public_key.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_FALSE(JwtEcdsaVerifyKeyManager().ValidateKey(public_key).ok());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, GetAndUsePrimitive) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  auto key_or = JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  auto key = key_or.ValueOrDie();

  auto sign_or =
      JwtEcdsaSignKeyManager().GetPrimitive<JwtPublicKeySignInternal>(key);
  ASSERT_THAT(sign_or.status(), IsOk());
  auto sign = std::move(sign_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or =
      sign->SignAndEncodeWithKid(raw_jwt, absl::nullopt);
  ASSERT_THAT(compact_or.status(), IsOk());
  auto compact = compact_or.ValueOrDie();

  JwtValidator validator =
      JwtValidatorBuilder().ExpectIssuer("issuer").Build().ValueOrDie();
  auto verify_or = JwtEcdsaVerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
      key.public_key());
  ASSERT_THAT(verify_or.status(), IsOk());
  auto verify = std::move(verify_or.ValueOrDie());

  util::StatusOr<VerifiedJwt> verified_jwt_or =
      verify->VerifyAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  util::StatusOr<std::string> issuer_or =
      verified_jwt_or.ValueOrDie().GetIssuer();
  ASSERT_THAT(issuer_or.status(), IsOk());
  EXPECT_THAT(issuer_or.ValueOrDie(), Eq("issuer"));

  JwtValidator validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build().ValueOrDie();
  EXPECT_FALSE(verify->VerifyAndDecode(compact, validator2).ok());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, VerifyFailsWithDifferentKey) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  auto key1_or = JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key1_or.status(), IsOk());
  auto key1 = key1_or.ValueOrDie();

  auto key2_or = JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key2_or.status(), IsOk());
  auto key2 = key2_or.ValueOrDie();

  auto sign1_or =
      JwtEcdsaSignKeyManager().GetPrimitive<JwtPublicKeySignInternal>(key1);
  ASSERT_THAT(sign1_or.status(), IsOk());
  auto sign1 = std::move(sign1_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or =
      sign1->SignAndEncodeWithKid(raw_jwt, absl::nullopt);
  ASSERT_THAT(compact_or.status(), IsOk());
  auto compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build().ValueOrDie();
  auto verify2_or = JwtEcdsaVerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
      key2.public_key());
  ASSERT_THAT(verify2_or.status(), IsOk());
  auto verify2 = std::move(verify2_or.ValueOrDie());

  EXPECT_FALSE(verify2->VerifyAndDecode(compact, validator).ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
