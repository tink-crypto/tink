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
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

class DilithiumKeyTest : public ::testing::Test {};

TEST_F(DilithiumKeyTest, Dilithium2KeysLength) {
  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Check keys size.
  EXPECT_EQ((key_pair->first).GetKeyData().size(),
            PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES);
  EXPECT_EQ((key_pair->second).GetKeyData().size(),
            PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES);
}

TEST_F(DilithiumKeyTest, Dilithium3KeysLength) {
  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Check keys size.
  EXPECT_EQ((key_pair->first).GetKeyData().size(),
            PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES);
  EXPECT_EQ((key_pair->second).GetKeyData().size(),
            PQCLEAN_DILITHIUM3_AVX2_CRYPTO_PUBLICKEYBYTES);
}

TEST_F(DilithiumKeyTest, Dilithium5KeysLength) {
  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Check keys size.
  EXPECT_EQ((key_pair->first).GetKeyData().size(),
            PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES);
  EXPECT_EQ((key_pair->second).GetKeyData().size(),
            PQCLEAN_DILITHIUM5_AVX2_CRYPTO_PUBLICKEYBYTES);
}

TEST_F(DilithiumKeyTest, DifferentContent) {
  // Generate key pair.
  util::StatusOr<
      std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
      key_pair = DilithiumPrivateKeyPqclean::GenerateKeyPair(
          PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES);

  ASSERT_THAT(key_pair.status(), IsOk());

  // Check keys content is different.
  EXPECT_NE(util::SecretDataAsStringView(key_pair->first.GetKeyData()),
            key_pair->second.GetKeyData());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
