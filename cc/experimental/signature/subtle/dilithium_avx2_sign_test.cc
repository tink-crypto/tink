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

#include "tink/experimental/signature/subtle/dilithium_avx2_sign.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
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
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/sign.h"
}

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

class DilithiumAvx2SignTest : public ::testing::Test {};

TEST_F(DilithiumAvx2SignTest, InvalidPrivateKeys) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  for (int keysize = 0; keysize < 2528; keysize++) {
    if (keysize == PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES) {
      // Valid key size.
      continue;
    }
    util::SecretData seeds_and_matrix(keysize, 'x');
    EXPECT_FALSE(DilithiumAvx2Sign::New(
                     DilithiumKey::FromSeedsAndMatrix(seeds_and_matrix))
                     .ok());
  }
}

TEST_F(DilithiumAvx2SignTest, SignatureLength) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  uint8_t pk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES];

  ASSERT_EQ(PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(pk, sk), 0);

  util::SecretData seeds_and_matrix = util::SecretDataFromStringView(
      absl::string_view(reinterpret_cast<char *>(sk),
                        PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES));

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      DilithiumAvx2Sign::New(
          DilithiumKey::FromSeedsAndMatrix(seeds_and_matrix));
  ASSERT_THAT(signer.status(), IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*std::move(signer))->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());

  // Check signature size.
  EXPECT_NE(*signature, message);
  EXPECT_EQ((*signature).size(), PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES);
}

TEST_F(DilithiumAvx2SignTest, Determinism) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  uint8_t pk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES];

  ASSERT_EQ(PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(pk, sk), 0);

  util::SecretData seeds_and_matrix = util::SecretDataFromStringView(
      absl::string_view(reinterpret_cast<char *>(sk),
                        PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES));

  // Create two signers based on same private key.
  util::StatusOr<std::unique_ptr<PublicKeySign>> first_signer =
      DilithiumAvx2Sign::New(
          DilithiumKey::FromSeedsAndMatrix(seeds_and_matrix));
  ASSERT_THAT(first_signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> second_signer =
      DilithiumAvx2Sign::New(
          DilithiumKey::FromSeedsAndMatrix(seeds_and_matrix));
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
  EXPECT_EQ((*first_signature).size(), PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES);

  EXPECT_NE(*second_signature, message);
  EXPECT_EQ((*second_signature).size(), PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES);

  // Check if signatures are equal.
  EXPECT_EQ(*first_signature, *second_signature);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
