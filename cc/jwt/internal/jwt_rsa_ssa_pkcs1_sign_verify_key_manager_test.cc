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
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
// #include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::JwtRsaSsaPkcs1PrivateKey;
using ::google::crypto::tink::JwtRsaSsaPkcs1PublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Not;

namespace {

JwtRsaSsaPkcs1KeyFormat CreateKeyFormat(JwtRsaSsaPkcs1Algorithm algorithm,
                                        int modulus_size_in_bits,
                                        int public_exponent) {
  JwtRsaSsaPkcs1KeyFormat key_format;
  key_format.set_algorithm(algorithm);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);
  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      subtle::SubtleUtilBoringSSL::bn2str(e.get(), BN_num_bytes(e.get()))
          .ValueOrDie());
  return key_format;
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, BasicsSign) {
  EXPECT_EQ(JwtRsaSsaPkcs1SignKeyManager().get_version(), 0);
  EXPECT_EQ(JwtRsaSsaPkcs1SignKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey");
  EXPECT_EQ(JwtRsaSsaPkcs1SignKeyManager().key_material_type(),
            google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE);
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, BasicsVerify) {
  EXPECT_EQ(JwtRsaSsaPkcs1VerifyKeyManager().get_version(), 0);
  EXPECT_EQ(JwtRsaSsaPkcs1VerifyKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey");
  EXPECT_EQ(JwtRsaSsaPkcs1VerifyKeyManager().key_material_type(),
            google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC);
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, ValidateEmptyPrivateKey) {
  EXPECT_THAT(
      JwtRsaSsaPkcs1SignKeyManager().ValidateKey(JwtRsaSsaPkcs1PrivateKey()),
      Not(IsOk()));
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, ValidateEmptyPublicKey) {
  EXPECT_THAT(
      JwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(JwtRsaSsaPkcs1PublicKey()),
      Not(IsOk()));
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(JwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(
                  JwtRsaSsaPkcs1KeyFormat()),
              Not(IsOk()));
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, ValidKeyFormatRS256) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  EXPECT_THAT(JwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, ValidateKeyFormatRS384) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS384, 3072, RSA_F4);
  EXPECT_THAT(JwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, ValidateKeyFormatRS512) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS512, 4096, RSA_F4);
  EXPECT_THAT(JwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, CreatePrivateKeyAndValidate) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  auto key_or = JwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  auto key = key_or.ValueOrDie();
  EXPECT_EQ(key.version(), 0);
  EXPECT_EQ(key.public_key().algorithm(), key_format.algorithm());
  EXPECT_THAT(JwtRsaSsaPkcs1SignKeyManager().ValidateKey(key), IsOk());

  // Change key to an invalid algorithm.
  key.mutable_public_key()->set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);
  EXPECT_FALSE(JwtRsaSsaPkcs1SignKeyManager().ValidateKey(key).ok());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, CreatePublicKeyAndValidate) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  auto key_or = JwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  auto public_key_or =
      JwtRsaSsaPkcs1SignKeyManager().GetPublicKey(key_or.ValueOrDie());
  auto public_key = public_key_or.ValueOrDie();
  EXPECT_THAT(JwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(public_key), IsOk());

  // Change key to an invalid algorithm.
  public_key.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);
  EXPECT_FALSE(JwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(public_key).ok());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, GetAndUsePrimitive) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  auto key_or = JwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  auto key = key_or.ValueOrDie();

  auto sign_or =
      JwtRsaSsaPkcs1SignKeyManager().GetPrimitive<JwtPublicKeySign>(key);
  ASSERT_THAT(sign_or.status(), IsOk());
  auto sign = std::move(sign_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or = sign->SignAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  auto compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().SetIssuer("issuer").Build();
  auto verify_or =
      JwtRsaSsaPkcs1VerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
          key.public_key());
  ASSERT_THAT(verify_or.status(), IsOk());
  auto verify = std::move(verify_or.ValueOrDie());

  util::StatusOr<VerifiedJwt> verified_jwt_or =
      verify->VerifyAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  util::StatusOr<std::string> issuer_or =
      verified_jwt_or.ValueOrDie().GetIssuer();
  ASSERT_THAT(issuer_or.status(), IsOk());
  EXPECT_THAT(issuer_or.ValueOrDie(), testing::Eq("issuer"));

  JwtValidator validator2 = JwtValidatorBuilder().SetIssuer("unknown").Build();
  EXPECT_FALSE(verify->VerifyAndDecode(compact, validator2).ok());
}

TEST(JwtRsaSsaPkcs1SignVerifyKeyManagerTest, VerifyFailsWithDifferentKey) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  auto key1_or = JwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key1_or.status(), IsOk());
  auto key1 = key1_or.ValueOrDie();

  auto key2_or = JwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key2_or.status(), IsOk());
  auto key2 = key2_or.ValueOrDie();

  auto sign1_or =
      JwtRsaSsaPkcs1SignKeyManager().GetPrimitive<JwtPublicKeySign>(key1);
  ASSERT_THAT(sign1_or.status(), IsOk());
  auto sign1 = std::move(sign1_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or = sign1->SignAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  auto compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();
  auto verify2_or =
      JwtRsaSsaPkcs1VerifyKeyManager().GetPrimitive<JwtPublicKeyVerify>(
          key2.public_key());
  ASSERT_THAT(verify2_or.status(), IsOk());
  auto verify2 = std::move(verify2_or.ValueOrDie());

  EXPECT_FALSE(verify2->VerifyAndDecode(compact, validator).ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
