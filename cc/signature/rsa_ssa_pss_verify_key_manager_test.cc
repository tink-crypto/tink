// Copyright 2018 Google Inc.
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

#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::RsaSsaPssKeyFormat;
using ::google::crypto::tink::RsaSsaPssPrivateKey;
using ::google::crypto::tink::RsaSsaPssPublicKey;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

TEST(RsaSsaPssVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey"));
}

TEST(RsaSsaPssVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(RsaSsaPssPublicKey()),
              Not(IsOk()));
}

RsaSsaPssKeyFormat CreateKeyFormat(HashType sig_hash, HashType mgf1_hash,
                                   int salt_length, int modulus_size_in_bits,
                                   int public_exponent) {
  RsaSsaPssKeyFormat key_format;
  auto params = key_format.mutable_params();
  params->set_sig_hash(sig_hash);
  params->set_mgf1_hash(mgf1_hash);
  params->set_salt_length(salt_length);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);

  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).ValueOrDie());

  return key_format;
}

RsaSsaPssKeyFormat ValidKeyFormat() {
  return CreateKeyFormat(HashType::SHA256, HashType::SHA256, 32, 3072, RSA_F4);
}

RsaSsaPssPrivateKey CreateValidPrivateKey() {
  return RsaSsaPssSignKeyManager().CreateKey(ValidKeyFormat()).ValueOrDie();
}

RsaSsaPssPublicKey CreateValidPublicKey() {
  return RsaSsaPssSignKeyManager()
      .GetPublicKey(CreateValidPrivateKey())
      .ValueOrDie();
}

// Checks that a public key generaed by the SignKeyManager is considered valid.
TEST(RsaSsaPssVerifyKeyManagerTest, PublicKeyValid) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key), IsOk());
}

TEST(RsaSsaPssVerifyKeyManagerTest, PublicKeyWrongVersion) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  key.set_version(1);
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RsaSsaPssVerifyKeyManagerTest, PublicKeyHashMismatchDisallowed) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  key.mutable_params()->set_sig_hash(HashType::SHA512);
  key.mutable_params()->set_mgf1_hash(HashType::SHA256);
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RsaSsaPssVerifyKeyManagerTest, PublicKeyHashMismatchDisallowed2) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  key.mutable_params()->set_sig_hash(HashType::SHA256);
  key.mutable_params()->set_mgf1_hash(HashType::SHA512);
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RsaSsaPssVerifyKeyManagerTest, PublicKeyUnkownHashDisallowed) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  key.mutable_params()->set_sig_hash(HashType::UNKNOWN_HASH);
  key.mutable_params()->set_mgf1_hash(HashType::UNKNOWN_HASH);
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RsaSsaPssVerifyKeyManagerTest, ValidateKeyFormatSmallModulusDisallowed) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  key.set_n("\x23");
  key.set_e("\x3");
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("only modulus size >= 2048")));
}

TEST(RsaSsaPssVerifyKeyManagerTest, NegativeSaltLengthFails) {
  RsaSsaPssPublicKey key = CreateValidPublicKey();
  key.mutable_params()->set_salt_length(-5);
  EXPECT_THAT(RsaSsaPssVerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RsaSsaPssSignKeyManagerTest, Create) {
  RsaSsaPssKeyFormat key_format =
      CreateKeyFormat(HashType::SHA256, HashType::SHA256, 32, 3072, RSA_F4);
  StatusOr<RsaSsaPssPrivateKey> private_key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key_or.status(), IsOk());
  RsaSsaPssPrivateKey private_key = private_key_or.ValueOrDie();
  RsaSsaPssPublicKey public_key =
      RsaSsaPssSignKeyManager().GetPublicKey(private_key).ValueOrDie();

  internal::RsaPrivateKey private_key_subtle;
  private_key_subtle.n = private_key.public_key().n();
  private_key_subtle.e = private_key.public_key().e();
  private_key_subtle.d = util::SecretDataFromStringView(private_key.d());
  private_key_subtle.p = util::SecretDataFromStringView(private_key.p());
  private_key_subtle.q = util::SecretDataFromStringView(private_key.q());
  private_key_subtle.dp = util::SecretDataFromStringView(private_key.dp());
  private_key_subtle.dq = util::SecretDataFromStringView(private_key.dq());
  private_key_subtle.crt = util::SecretDataFromStringView(private_key.crt());

  auto direct_signer_or = subtle::RsaSsaPssSignBoringSsl::New(
      private_key_subtle, {crypto::tink::subtle::HashType::SHA256,
                           crypto::tink::subtle::HashType::SHA256, 32});

  auto verifier_or =
      RsaSsaPssVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(
      verifier_or.ValueOrDie()->Verify(
          direct_signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
      IsOk());
}

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  HashType sig_hash;
  HashType mgf1_hash;
  int salt_length;
};

// clang-format off
static const NistTestVector* nist_test_vector = new NistTestVector({
    absl::HexStringToBytes(
        "a47d04e7cacdba4ea26eca8a4c6e14563c2ce03b623b768c0d49868a57121301dbf783"
        "d82f4c055e73960e70550187d0af62ac3496f0a3d9103c2eb7919a72752fa7ce8c688d"
        "81e3aee99468887a15288afbb7acb845b7c522b5c64e678fcd3d22feb84b44272700be"
        "527d2b2025a3f83c2383bf6a39cf5b4e48b3cf2f56eef0dfff18555e31037b91524869"
        "4876f3047814415164f2c660881e694b58c28038a032ad25634aad7b39171dee368e3d"
        "59bfb7299e4601d4587e68caaf8db457b75af42fc0cf1ae7caced286d77fac6cedb03a"
        "d94f1433d2c94d08e60bc1fdef0543cd2951e765b38230fdd18de5d2ca627ddc032fe0"
        "5bbd2ff21e2db1c2f94d8b"),
    absl::HexStringToBytes("10e43f"),
    absl::HexStringToBytes(
        "e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb1b"
        "126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22aeb4"
        "0f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173187b4f"
        "09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6"),
    absl::HexStringToBytes(
        "4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc08779a"
        "374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4cf348"
        "cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63a0c057"
        "2b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48b9f162cf"
        "6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b1dc593091d"
        "b5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b1b063089ae7e"
        "2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f95ff0111881e650"
        "ce61f251d9c3a629ef222d"),
    HashType::SHA256,
    HashType::SHA256,
    32});
// clang-format on

TEST(RsaSsaPssVerifyKeyManagerTest, TestVector) {
  RsaSsaPssPublicKey key;
  key.mutable_params()->set_mgf1_hash(nist_test_vector->mgf1_hash);
  key.mutable_params()->set_sig_hash(nist_test_vector->sig_hash);
  key.mutable_params()->set_salt_length(nist_test_vector->salt_length);
  key.set_version(0);
  key.set_n(nist_test_vector->n);
  key.set_e(nist_test_vector->e);
  auto result = RsaSsaPssVerifyKeyManager().GetPrimitive<PublicKeyVerify>(key);
  ASSERT_THAT(result.status(), IsOk());
  EXPECT_THAT(result.ValueOrDie()->Verify(nist_test_vector->signature,
                                          nist_test_vector->message),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
