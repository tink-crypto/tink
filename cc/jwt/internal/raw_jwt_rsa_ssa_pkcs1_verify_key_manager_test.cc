// Copyright 2021 Google LLC
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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_verify_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::JwtRsaSsaPkcs1PrivateKey;
using ::google::crypto::tink::JwtRsaSsaPkcs1PublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

namespace {

TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, Basics) {
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(
      RawJwtRsaSsaPkcs1VerifyKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"));
}

TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(
                  JwtRsaSsaPkcs1PublicKey()),
              Not(IsOk()));
}

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

JwtRsaSsaPkcs1KeyFormat ValidKeyFormat() {
  return CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 3072, RSA_F4);
}

JwtRsaSsaPkcs1PrivateKey CreateValidPrivateKey() {
  return RawJwtRsaSsaPkcs1SignKeyManager()
      .CreateKey(ValidKeyFormat())
      .ValueOrDie();
}

JwtRsaSsaPkcs1PublicKey CreateValidPublicKey() {
  return RawJwtRsaSsaPkcs1SignKeyManager()
      .GetPublicKey(CreateValidPrivateKey())
      .ValueOrDie();
}

// Checks that a public key generaed by the SignKeyManager is considered valid.
TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, PublicKeyValid) {
  JwtRsaSsaPkcs1PublicKey key = CreateValidPublicKey();
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(key), IsOk());
}

TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, PublicKeyWrongVersion) {
  JwtRsaSsaPkcs1PublicKey key = CreateValidPublicKey();
  key.set_version(1);
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(key),
              Not(IsOk()));
}

TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, KeyWithUnkownAlgorithmInvalid) {
  JwtRsaSsaPkcs1PublicKey key = CreateValidPublicKey();
  key.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(key),
              Not(IsOk()));
}

TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, KeyFormatWithSmallModulusInvalid) {
  JwtRsaSsaPkcs1PublicKey key = CreateValidPublicKey();
  key.set_n("\x23");
  key.set_e("\x3");
  EXPECT_THAT(RawJwtRsaSsaPkcs1VerifyKeyManager().ValidateKey(key),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("only modulus size >= 2048")));
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, Create) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 3072, RSA_F4);
  StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      RawJwtRsaSsaPkcs1SignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  subtle::SubtleUtilBoringSSL::RsaPrivateKey private_key_subtle;
  private_key_subtle.n = private_key->public_key().n();
  private_key_subtle.e = private_key->public_key().e();
  private_key_subtle.d = util::SecretDataFromStringView(private_key->d());
  private_key_subtle.p = util::SecretDataFromStringView(private_key->p());
  private_key_subtle.q = util::SecretDataFromStringView(private_key->q());
  private_key_subtle.dp = util::SecretDataFromStringView(private_key->dp());
  private_key_subtle.dq = util::SecretDataFromStringView(private_key->dq());
  private_key_subtle.crt = util::SecretDataFromStringView(private_key->crt());

  util::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::RsaSsaPkcs1SignBoringSsl::New(
          private_key_subtle, {crypto::tink::subtle::HashType::SHA256});

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RawJwtRsaSsaPkcs1VerifyKeyManager().GetPrimitive<PublicKeyVerify>(
          *public_key);
  ASSERT_THAT(verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> sig = (*direct_signer)->Sign(message);
  ASSERT_THAT(sig.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(*sig, message), IsOk());
}

TEST(RawJwtRsaSsaPkcs1VerifyKeyManagerTest, NistTestVector) {
  // Test vector from
  // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
  struct NistTestVector {
    std::string n;
    std::string e;
    std::string message;
    std::string signature;
    JwtRsaSsaPkcs1Algorithm algorithm;
  };

  const NistTestVector nist_test_vector{
      absl::HexStringToBytes(
          "c9548608087bed6be0a4623b9d849aa0b4b4b6114ad0a7d82578076ceefe26ce48d1"
          "448e16d69963510e1e5fc658f3cf8f32a489b62d93fec1cdea6e1dde3feba04bb6a0"
          "34518d83fd6138ea999982ab95d6a03517688ab6f8411c4a96b3e79d4141b8f68338"
          "a9baa99f4e2c7845b573981061c5fd29d5fc21833ff1b030b2deb651e51a291168e2"
          "b45ab4202dcd97b891925c75338e0e648d9d9ad325c10884e1fcdccc1c547b4a9c36"
          "aef939e8802b62405d6e3d358ffa88f206b976b87f8b12b827b0ee7823f9d1955f47"
          "f8678f7843b4cd03777e46717060e82bf149b36d4cf3d0bc7e4d0effde51a72f4ced"
          "8e8e5b11bdb135825ff08873e2f776929abb"),
      absl::HexStringToBytes("3c7bf9"),
      absl::HexStringToBytes(
          "bf082fa4b79f32849e8fae692696fc978ccb648c6e278d9bde4338d7b4632e3228b4"
          "77e6a0d2cd14c68d51abdeed7c8c577457ec9fa2eff93cbf03c019d4014e1dfb3115"
          "02d82f9265689e2d19f91b61c17a701c9ef50a69a55aae4cd57e67edc763c3f987ba"
          "3e46a2a6ffb680c3c25df46716e61228c832419e9f43916a4959"),
      absl::HexStringToBytes(
          "621120a71ff2a182dd2997beb2480f54be516b79a4c202d1d6f59270f8e4d4dbd625"
          "ac52fe0e49c5fd69dc0d15fb19ec58c9312a8161a61cb878abcb11399937f28ff080"
          "3877c239ce0b7c4cbc1e23eca22746b071b2716475424c12944660b929b6240aebe8"
          "47fcb94f63d212f3aa538515dc061e9810fdb0adeb374d0f69d24fd52c94e42668a4"
          "8fc0a57819952a40efb732cfa08b3d2b371780aea97be34efb5239994d7ee7c6ab91"
          "34b76711e76813ad5f5c3a5c95399e907650534dbfafec900c21be1308ddff6eda52"
          "5f35e4fb3d275de46250ea1e4b96b60bd125b85f6c52b5419a725cd69b10cefd0901"
          "abe7f9e15940594cf811e34c60f38768244c"),
      JwtRsaSsaPkcs1Algorithm::RS256};

  JwtRsaSsaPkcs1PublicKey key;
  key.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  key.set_version(0);
  key.set_n(nist_test_vector.n);
  key.set_e(nist_test_vector.e);
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RawJwtRsaSsaPkcs1VerifyKeyManager().GetPrimitive<PublicKeyVerify>(key);
  EXPECT_THAT(verifier.status(), IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(nist_test_vector.signature, nist_test_vector.message),
      IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
