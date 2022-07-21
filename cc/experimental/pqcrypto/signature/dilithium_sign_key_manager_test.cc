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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_verify.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium2aes/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3aes/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5aes/api.h"
}

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::DilithiumPublicKeyPqclean;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::EnumsPqcrypto;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::DilithiumKeyFormat;
using ::google::crypto::tink::DilithiumParams;
using ::google::crypto::tink::DilithiumPrivateKey;
using ::google::crypto::tink::DilithiumPublicKey;
using ::google::crypto::tink::DilithiumSeedExpansion;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

struct DilithiumTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t public_key_size;
  DilithiumSeedExpansion seed_expansion;
};

using DilithiumSignKeyManagerTest = testing::TestWithParam<DilithiumTestCase>;

// Helper function that returns a valid dilithium key format.
StatusOr<DilithiumKeyFormat> CreateValidKeyFormat(
    int32 private_key_size, DilithiumSeedExpansion seed_expansion) {
  DilithiumKeyFormat key_format;
  DilithiumParams* params = key_format.mutable_params();
  params->set_key_size(private_key_size);
  params->set_seed_expansion(seed_expansion);

  return key_format;
}

TEST(DilithiumSignKeyManagerTest, Basic) {
  EXPECT_THAT(DilithiumSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(DilithiumSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(DilithiumSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.DilithiumPrivateKey"));
}

TEST_P(DilithiumSignKeyManagerTest, ValidateKeyFormat) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  EXPECT_THAT(DilithiumSignKeyManager().ValidateKeyFormat(*key_format), IsOk());
}

TEST_P(DilithiumSignKeyManagerTest, PrivateKeyWrongVersion) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<DilithiumPrivateKey> private_key =
      DilithiumSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  private_key->set_version(1);
  EXPECT_THAT(DilithiumSignKeyManager().ValidateKey(*private_key), Not(IsOk()));
}

TEST_P(DilithiumSignKeyManagerTest, CreateKey) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<DilithiumPrivateKey> private_key =
      DilithiumSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->version(), Eq(0));
  EXPECT_THAT(private_key->public_key().version(), Eq(private_key->version()));
  EXPECT_THAT(private_key->key_value(), SizeIs(test_case.private_key_size));
  EXPECT_THAT(private_key->public_key().key_value(),
              SizeIs(test_case.public_key_size));
}

TEST_P(DilithiumSignKeyManagerTest, CreateKeyValid) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<DilithiumPrivateKey> private_key =
      DilithiumSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(DilithiumSignKeyManager().ValidateKey(*private_key), IsOk());
}

TEST_P(DilithiumSignKeyManagerTest, CreateKeyAlwaysNew) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  absl::flat_hash_set<std::string> keys;
  int num_tests = 100;
  for (int i = 0; i < num_tests; ++i) {
    StatusOr<DilithiumPrivateKey> private_key =
        DilithiumSignKeyManager().CreateKey(*key_format);
    ASSERT_THAT(private_key, IsOk());
    keys.insert(private_key->key_value());
  }
  EXPECT_THAT(keys, SizeIs(num_tests));
}

TEST_P(DilithiumSignKeyManagerTest, GetPublicKey) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<DilithiumPrivateKey> private_key =
      DilithiumSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  StatusOr<DilithiumPublicKey> public_key_or =
      DilithiumSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key_or, IsOk());

  EXPECT_THAT(public_key_or->version(),
              Eq(private_key->public_key().version()));
  EXPECT_THAT(public_key_or->key_value(),
              Eq(private_key->public_key().key_value()));
}

TEST_P(DilithiumSignKeyManagerTest, Create) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  util::StatusOr<DilithiumPrivateKey> private_key =
      DilithiumSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      DilithiumSignKeyManager().GetPrimitive<PublicKeySign>(*private_key);
  ASSERT_THAT(signer, IsOk());

  util::StatusOr<DilithiumPublicKeyPqclean> dilithium_public_key =
      DilithiumPublicKeyPqclean::NewPublicKey(
          private_key->public_key().key_value(),
          EnumsPqcrypto::ProtoToSubtle(test_case.seed_expansion));

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      subtle::DilithiumAvx2Verify::New(*dilithium_public_key);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(DilithiumSignKeyManagerTest, CreateDifferentKey) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumKeyFormat> key_format = CreateValidKeyFormat(
      test_case.private_key_size, test_case.seed_expansion);
  ASSERT_THAT(key_format, IsOk());

  util::StatusOr<DilithiumPrivateKey> private_key =
      DilithiumSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      DilithiumSignKeyManager().GetPrimitive<PublicKeySign>(*private_key);
  ASSERT_THAT(signer, IsOk());

  std::string bad_public_key_data(test_case.public_key_size, '@');
  util::StatusOr<DilithiumPublicKeyPqclean> dilithium_public_key =
      DilithiumPublicKeyPqclean::NewPublicKey(
          bad_public_key_data,
          EnumsPqcrypto::ProtoToSubtle(test_case.seed_expansion));
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      subtle::DilithiumAvx2Verify::New(*dilithium_public_key);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    DilithiumSignKeyManagerTests, DilithiumSignKeyManagerTest,
    testing::ValuesIn<DilithiumTestCase>({
        {"Dilithium2", PQCLEAN_DILITHIUM2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM2_CRYPTO_PUBLICKEYBYTES,
         DilithiumSeedExpansion::SEED_EXPANSION_SHAKE},
        {"Dilithium3", PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES,
         DilithiumSeedExpansion::SEED_EXPANSION_SHAKE},
        {"Dilithium5", PQCLEAN_DILITHIUM5_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM5_CRYPTO_PUBLICKEYBYTES,
         DilithiumSeedExpansion::SEED_EXPANSION_SHAKE},
        {"Dilithium2Aes", PQCLEAN_DILITHIUM2AES_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM2AES_CRYPTO_PUBLICKEYBYTES,
         DilithiumSeedExpansion::SEED_EXPANSION_AES},
        {"Dilithium3Aes", PQCLEAN_DILITHIUM3AES_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM3AES_CRYPTO_PUBLICKEYBYTES,
         DilithiumSeedExpansion::SEED_EXPANSION_AES},
        {"Dilithium5Aes", PQCLEAN_DILITHIUM5AES_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM5AES_CRYPTO_PUBLICKEYBYTES,
         DilithiumSeedExpansion::SEED_EXPANSION_AES},
    }),
    [](const testing::TestParamInfo<DilithiumSignKeyManagerTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace

}  // namespace tink
}  // namespace crypto
