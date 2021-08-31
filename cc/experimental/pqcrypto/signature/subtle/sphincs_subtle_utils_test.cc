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

#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_helper_pqclean.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-robust/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-simple/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-robust/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-simple/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-robust/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-simple/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-robust/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-simple/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-robust/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-simple/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-robust/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-simple/aesni/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-simple/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-robust/avx2/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-simple/avx2/api.h"
}

// Definitions of the three possible sphincs key sizes.
#define SPHINCSKEYSIZE64 64
#define SPHINCSKEYSIZE96 96
#define SPHINCSKEYSIZE128 128

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

struct SphincsUtilsTestCase {
  std::string test_name;
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureLengthType sig_length_type;
  int32_t private_key_size;
  int32_t public_key_size;
};

using SphincsUtilsTest = testing::TestWithParam<SphincsUtilsTestCase>;

TEST_P(SphincsUtilsTest, SphincsKeysLength) {
  const SphincsUtilsTestCase& test_case = GetParam();

  SphincsParams params(test_case.hash_type, test_case.variant,
                       test_case.private_key_size, test_case.sig_length_type);

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Check keys size.
  EXPECT_EQ(key_pair->GetPrivateKey().Get().size(), test_case.private_key_size);
  EXPECT_EQ(key_pair->GetPublicKey().Get().size(), test_case.public_key_size);
}

TEST_P(SphincsUtilsTest, DifferentContent) {
  const SphincsUtilsTestCase& test_case = GetParam();

  SphincsParams params(test_case.hash_type, test_case.variant,
                       test_case.private_key_size, test_case.sig_length_type);

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair.status(), IsOk());

  // Check keys content is different.
  EXPECT_NE(util::SecretDataAsStringView(key_pair->GetPrivateKey().Get()),
            key_pair->GetPublicKey().Get());
}

TEST(SphincsUtilsTest, InvalidKeySize) {
  for (int keysize = 0; keysize <= SPHINCSKEYSIZE128; keysize++) {
    if (keysize == SPHINCSKEYSIZE64 || keysize == SPHINCSKEYSIZE96 ||
        keysize == SPHINCSKEYSIZE128) {
      // Valid key size.
      continue;
    }
    EXPECT_FALSE(ValidateKeySize(keysize).ok());
  }
}

INSTANTIATE_TEST_SUITE_P(
    SphincsUtilsTests, SphincsUtilsTest,
    testing::ValuesIn<SphincsUtilsTestCase>(
        {{"SPHINCSHARAKA128FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSHARAKA128FROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FROBUST_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSHARAKA128SROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SROBUST_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_AESNI_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSHARAKA192FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSHARAKA192FROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FROBUST_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSHARAKA192SROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SROBUST_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_AESNI_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSHARAKA256FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSHARAKA256FROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FROBUST_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSHARAKA256SROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SROBUST_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_AESNI_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_AESNI_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256128FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHA256128FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256192FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHA256192FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHA256192SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256256FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHA256256FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHA256256SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256128FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256192FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256256FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::F,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureLengthType::S,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_AVX2_CRYPTO_PUBLICKEYBYTES}}),
    [](const testing::TestParamInfo<SphincsUtilsTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
