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

#include <string>
#include <utility>

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
using ::crypto::tink::test::IsOkAndHolds;
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
            KeyData::ASYMMETRIC_PRIVATE);
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, BasicsVerify) {
  EXPECT_EQ(JwtEcdsaVerifyKeyManager().get_version(), 0);
  EXPECT_EQ(JwtEcdsaVerifyKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey");
  EXPECT_EQ(JwtEcdsaVerifyKeyManager().key_material_type(),
            KeyData::ASYMMETRIC_PUBLIC);
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
  util::StatusOr<JwtEcdsaPrivateKey> key =
      JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_EQ(key->version(), 0);
  EXPECT_EQ(key->public_key().algorithm(), key_format.algorithm());
  EXPECT_THAT(JwtEcdsaSignKeyManager().ValidateKey(*key), IsOk());

  // Change key to an invalid algorithm.
  key->mutable_public_key()->set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_FALSE(JwtEcdsaSignKeyManager().ValidateKey(*key).ok());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, CreatePublicKeyAndValidate) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  util::StatusOr<JwtEcdsaPrivateKey> key =
      JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaSignKeyManager().GetPublicKey(*key);
  EXPECT_THAT(JwtEcdsaVerifyKeyManager().ValidateKey(*public_key), IsOk());

  // Change key to an invalid algorithm.
  public_key->set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_FALSE(JwtEcdsaVerifyKeyManager().ValidateKey(*public_key).ok());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, GetAndUsePrimitive) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  util::StatusOr<JwtEcdsaPrivateKey> key =
      JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>> sign =
      JwtEcdsaSignKeyManager().GetPrimitive<JwtPublicKeySignInternal>(*key);
  ASSERT_THAT(sign.status(), IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      (*sign)->SignAndEncodeWithKid(*raw_jwt, absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      JwtEcdsaVerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
          key->public_key());
  ASSERT_THAT(verify.status(), IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  util::StatusOr<std::string> issuer = verified_jwt->GetIssuer();
  EXPECT_THAT(issuer, IsOkAndHolds("issuer"));

  util::StatusOr<JwtValidator> validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build();
  ASSERT_THAT(validator2.status(), IsOk());
  EXPECT_FALSE((*verify)->VerifyAndDecode(*compact, *validator2).ok());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, GetAndUsePrimitivesWithCustomKid) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  util::StatusOr<JwtEcdsaPrivateKey> key =
      JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  key->mutable_public_key()->mutable_custom_kid()->set_value(
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

  util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>> sign =
      JwtEcdsaSignKeyManager().GetPrimitive<JwtPublicKeySignInternal>(*key);
  ASSERT_THAT(sign.status(), IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      (*sign)->SignAndEncodeWithKid(*raw_jwt, absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());

  // parse header and check "kid"
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header.status(), IsOk());
  auto it = header->fields().find("kid");
  ASSERT_FALSE(it == header->fields().end());
  EXPECT_THAT(it->second.string_value(),
              Eq("Lorem ipsum dolor sit amet, consectetur adipiscing elit"));

  // validate token
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      JwtEcdsaVerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
          key->public_key());
  ASSERT_THAT(verify.status(), IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  util::StatusOr<std::string> issuer = verified_jwt->GetIssuer();
  ASSERT_THAT(issuer.status(), IsOk());
  EXPECT_THAT(*issuer, Eq("issuer"));

  // passing a kid when custom_kid is set should fail
  util::StatusOr<std::string> compact2 =
      (*sign)->SignAndEncodeWithKid(*raw_jwt, "kid123");
  ASSERT_FALSE(compact2.ok());
}

TEST(JwtEcdsaSignVerifyKeyManagerTest, VerifyFailsWithDifferentKey) {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  util::StatusOr<JwtEcdsaPrivateKey> key1 =
      JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key1.status(), IsOk());

  util::StatusOr<JwtEcdsaPrivateKey> key2 =
      JwtEcdsaSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key2.status(), IsOk());

  util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>> sign1 =
      JwtEcdsaSignKeyManager().GetPrimitive<JwtPublicKeySignInternal>(*key1);
  ASSERT_THAT(sign1.status(), IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      (*sign1)->SignAndEncodeWithKid(*raw_jwt, absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().AllowMissingExpiration().Build();
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify2 =
      JwtEcdsaVerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
          key2->public_key());
  ASSERT_THAT(verify2.status(), IsOk());

  EXPECT_FALSE((*verify2)->VerifyAndDecode(*compact, *validator).ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
