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

#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
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
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

struct DilithiumTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t public_key_size;
  DilithiumSeedExpansion seed_expansion;
};

using DilithiumKeyTest = testing::TestWithParam<DilithiumTestCase>;

TEST_P(DilithiumKeyTest, DilithiumKeysLength) {
  const DilithiumTestCase& test_case = GetParam();

  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          test_case.private_key_size, test_case.seed_expansion);

  ASSERT_THAT(key_pair, IsOk());

  // Check keys size.
  EXPECT_EQ((key_pair->first).GetKeyData().size(), test_case.private_key_size);
  EXPECT_EQ((key_pair->second).GetKeyData().size(), test_case.public_key_size);
}

TEST_P(DilithiumKeyTest, DifferentContent) {
  const DilithiumTestCase& test_case = GetParam();

  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          test_case.private_key_size, test_case.seed_expansion);

  ASSERT_THAT(key_pair, IsOk());

  // Check keys content is different.
  EXPECT_NE(util::SecretDataAsStringView(key_pair->first.GetKeyData()),
            key_pair->second.GetKeyData());
}

INSTANTIATE_TEST_SUITE_P(
    DilithiumKeyTesta, DilithiumKeyTest,
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
    [](const testing::TestParamInfo<DilithiumKeyTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
