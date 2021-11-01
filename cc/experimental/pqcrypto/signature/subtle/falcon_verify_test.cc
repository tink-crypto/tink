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

#include "tink/experimental/pqcrypto/signature/subtle/falcon_verify.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/falcon-1024/avx2/api.h"
#include "third_party/pqclean/crypto_sign/falcon-512/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using crypto::tink::util::Status;

struct FalconTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t signature_length;
};

using FalconVerifyTest = testing::TestWithParam<FalconTestCase>;

TEST_P(FalconVerifyTest, BasicSignVerify) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer.status(), IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier.status(), IsOk());

  // Verify signature.
  Status status = (*verifier)->Verify(*signature, message);
  EXPECT_THAT(status, IsOk());
}

TEST_P(FalconVerifyTest, FailsWithWrongSignature) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer.status(), IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier.status(), IsOk());

  // Verify signature.
  Status status =
      (*verifier)->Verify(*signature + "some trailing data", message);
  EXPECT_FALSE(status.ok());
}

TEST_P(FalconVerifyTest, FailsWithWrongMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer.status(), IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier.status(), IsOk());

  // Verify signature.
  Status status = (*verifier)->Verify(*signature, "some bad message");
  EXPECT_FALSE(status.ok());
}

TEST_P(FalconVerifyTest, FailsWithBytesFlipped) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer.status(), IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier.status(), IsOk());

  // Invalidate one signature byte.
  (*signature)[0] ^= 1;

  // Verify signature.
  Status status = (*verifier)->Verify(*signature, message);
  EXPECT_FALSE(status.ok());
}

TEST_P(FalconVerifyTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  const FalconTestCase& test_case = GetParam();

  // Generate falcon key pair.
  util::StatusOr<FalconKeyPair> key_pair =
      GenerateFalconKeyPair(test_case.private_key_size);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  EXPECT_THAT(FalconVerify::New(key_pair->GetPublicKey()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

INSTANTIATE_TEST_SUITE_P(
    FalconVerifyTests, FalconVerifyTest,
    testing::ValuesIn<FalconTestCase>({{"Falcon512", kFalcon512PrivateKeySize,
                                        PQCLEAN_FALCON512_AVX2_CRYPTO_BYTES},
                                       {"Falcon1024", kFalcon1024PrivateKeySize,
                                        PQCLEAN_FALCON1024_AVX2_CRYPTO_BYTES}}),
    [](const testing::TestParamInfo<FalconVerifyTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
