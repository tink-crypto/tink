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

#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"

#include <climits>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Not;

struct FalconTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t public_key_size;
};

using FalconUtilsTest = testing::TestWithParam<FalconTestCase>;

TEST_P(FalconUtilsTest, FalconKeyGeneration) {
  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair, IsOk());

  // Check keys size.
  EXPECT_EQ(key_pair->GetPrivateKey().GetKey().size(),
            test_case.private_key_size);
  EXPECT_EQ(key_pair->GetPublicKey().GetKey().size(),
            test_case.public_key_size);
}

TEST_P(FalconUtilsTest, DifferentContent) {
  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair, IsOk());

  // Check keys content is different.
  EXPECT_NE(util::SecretDataAsStringView(key_pair->GetPrivateKey().GetKey()),
            key_pair->GetPublicKey().GetKey());
}

TEST(FalconUtilsTest, ValidPrivateKeySize) {
  EXPECT_THAT(ValidateFalconPrivateKeySize(kFalcon1024PrivateKeySize), IsOk());
  EXPECT_THAT(ValidateFalconPrivateKeySize(kFalcon512PrivateKeySize), IsOk());
}

TEST(FalconUtilsTest, InvalidPrivateKeySize) {
  std::vector<int32_t> invalid_keysizes{0,
                                        -1,
                                        kFalcon1024PrivateKeySize - 1,
                                        kFalcon1024PrivateKeySize + 1,
                                        INT_MAX,
                                        INT_MIN};
  for (int i = 0; i < invalid_keysizes.size(); i++) {
    EXPECT_FALSE(ValidateFalconPrivateKeySize(invalid_keysizes[i]).ok());
  }
}

TEST(FalconUtilsTest, ValidPublicKeySize) {
  EXPECT_THAT(ValidateFalconPublicKeySize(kFalcon1024PublicKeySize), IsOk());
  EXPECT_THAT(ValidateFalconPublicKeySize(kFalcon512PublicKeySize), IsOk());
}

TEST(FalconUtilsTest, InvalidPublicKeySize) {
  std::vector<int32_t> invalid_keysizes{0,
                                        -1,
                                        kFalcon1024PublicKeySize - 1,
                                        kFalcon1024PublicKeySize + 1,
                                        INT_MAX,
                                        INT_MIN};
  for (int i = 0; i < invalid_keysizes.size(); i++) {
    EXPECT_FALSE(ValidateFalconPublicKeySize(invalid_keysizes[i]).ok());
  }
}

TEST(FalconUtilsTest, InvalidPrivateKey) {
  std::string bad_private_key_data = "bad private key";
  util::StatusOr<FalconPrivateKeyPqclean> private_key =
      FalconPrivateKeyPqclean::NewPrivateKey(
          util::SecretDataFromStringView(bad_private_key_data));

  EXPECT_THAT(private_key.status(), testing::Not(IsOk()));
}

TEST(FalconUtilsTest, InvalidPubliceKey) {
  std::string bad_public_key_data = "bad public key";
  util::StatusOr<FalconPublicKeyPqclean> public_key =
      FalconPublicKeyPqclean::NewPublicKey(bad_public_key_data);

  EXPECT_THAT(public_key, Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    FalconUtilsTests, FalconUtilsTest,
    testing::ValuesIn<FalconTestCase>(
        {{"Falcon512", kFalcon512PrivateKeySize, kFalcon512PublicKeySize},
         {"Falcon1024", kFalcon1024PrivateKeySize, kFalcon1024PublicKeySize}}),
    [](const testing::TestParamInfo<FalconUtilsTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
