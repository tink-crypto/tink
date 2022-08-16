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

#include "tink/experimental/pqcrypto/signature/subtle/falcon_sign.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/falcon-1024/api.h"
#include "third_party/pqclean/crypto_sign/falcon-512/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

struct FalconTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t signature_length;
};

using FalconSignTest = testing::TestWithParam<FalconTestCase>;

TEST_P(FalconSignTest, ValidSignatureLength) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = ((*signer)->Sign(message));
  ASSERT_THAT(signature, IsOk());

  // Check signature size.
  EXPECT_NE(*signature, message);
  EXPECT_LE((*signature).size(), test_case.signature_length);
}

TEST_P(FalconSignTest, NonDeterminism) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair, IsOk());

  // Create two signers based on same private key.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer, IsOk());

  // Sign the same message twice, using the same private key.
  std::string message = "message to be signed";
  util::StatusOr<std::string> first_signature = ((*signer))->Sign(message);
  ASSERT_THAT(first_signature, IsOk());

  util::StatusOr<std::string> second_signature = ((*signer))->Sign(message);
  ASSERT_THAT(second_signature, IsOk());

  // Check signatures size.
  EXPECT_NE(*first_signature, message);
  EXPECT_LE((*first_signature).size(), test_case.signature_length);

  EXPECT_NE(*second_signature, message);
  EXPECT_LE((*second_signature).size(), test_case.signature_length);

  // Check if signatures are equal.
  EXPECT_NE(*first_signature, *second_signature);
}

TEST_P(FalconSignTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  EXPECT_THAT(FalconSign::New(key_pair->GetPrivateKey()).status(),
              test::StatusIs(absl::StatusCode::kInternal));
}

INSTANTIATE_TEST_SUITE_P(
    FalconSignTests, FalconSignTest,
    testing::ValuesIn<FalconTestCase>({{"Falcon512", kFalcon512PrivateKeySize,
                                        PQCLEAN_FALCON512_CRYPTO_BYTES},
                                       {"Falcon1024", kFalcon1024PrivateKeySize,
                                        PQCLEAN_FALCON1024_CRYPTO_BYTES}}),
    [](const testing::TestParamInfo<FalconSignTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
