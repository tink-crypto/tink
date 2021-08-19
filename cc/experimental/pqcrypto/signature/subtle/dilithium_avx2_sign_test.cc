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

#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_sign.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "testing/base/public/googletest.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {
namespace {

struct DilithiumTestCase {
  std::string test_name;
  int key_size = 0;
  int signature_length = 0;
};

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using crypto::tink::util::Status;

using DilithiumAvx2SignTest = testing::TestWithParam<DilithiumTestCase>;

TEST(DilithiumAvx2SignTest, InvalidPrivateKeys) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  for (int keysize = 0;
       keysize <= PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES; keysize++) {
    if (keysize == PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES ||
        keysize == PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES ||
        keysize == PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES) {
      // Valid key size.
      continue;
    }

    util::SecretData key_data(keysize, 'x');
    EXPECT_FALSE(DilithiumAvx2Sign::New(
                     *DilithiumPrivateKeyPqclean::NewPrivateKey(key_data))
                     .ok());
  }
}

TEST_P(DilithiumAvx2SignTest, SignatureLength) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const DilithiumTestCase& test_case = GetParam();

  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair =
          DilithiumPrivateKeyPqclean::GenerateKeyPair(test_case.key_size);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      DilithiumAvx2Sign::New(key_pair->first);
  ASSERT_THAT(signer.status(), IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*std::move(signer))->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());

  // Check signature size.
  EXPECT_NE(*signature, message);
  EXPECT_EQ((*signature).size(), test_case.signature_length);
}

TEST_P(DilithiumAvx2SignTest, Determinism) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const DilithiumTestCase& test_case = GetParam();

  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair =
          DilithiumPrivateKeyPqclean::GenerateKeyPair(test_case.key_size);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Create two signers based on same private key.
  util::StatusOr<std::unique_ptr<PublicKeySign>> first_signer =
      DilithiumAvx2Sign::New(key_pair->first);
  ASSERT_THAT(first_signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> second_signer =
      DilithiumAvx2Sign::New(key_pair->first);
  ASSERT_THAT(second_signer.status(), IsOk());

  // Sign the same message twice, using the same private key.
  std::string message = "message to be signed";
  util::StatusOr<std::string> first_signature =
      (*std::move(first_signer))->Sign(message);
  ASSERT_THAT(first_signature.status(), IsOk());

  util::StatusOr<std::string> second_signature =
      (*std::move(second_signer))->Sign(message);
  ASSERT_THAT(second_signature.status(), IsOk());

  // Check signatures size.
  EXPECT_NE(*first_signature, message);
  EXPECT_EQ((*first_signature).size(), test_case.signature_length);

  EXPECT_NE(*second_signature, message);
  EXPECT_EQ((*second_signature).size(), test_case.signature_length);

  // Check if signatures are equal.
  EXPECT_EQ(*first_signature, *second_signature);
}

TEST_P(DilithiumAvx2SignTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  const DilithiumTestCase& test_case = GetParam();

  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair =
          DilithiumPrivateKeyPqclean::GenerateKeyPair(test_case.key_size);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Create a new signer.
  EXPECT_THAT(DilithiumAvx2Sign::New(key_pair->first).status(),
              StatusIs(util::error::INTERNAL));
}

INSTANTIATE_TEST_SUITE_P(
    DilithiumAvx2SignTests, DilithiumAvx2SignTest,
    testing::ValuesIn<DilithiumTestCase>({
        {"Dilithium2", PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES},
        {"Dilithium3", PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM3_AVX2_CRYPTO_BYTES},
        {"Dilithium5", PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM5_AVX2_CRYPTO_BYTES},
    }),
    [](const testing::TestParamInfo<DilithiumAvx2SignTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
