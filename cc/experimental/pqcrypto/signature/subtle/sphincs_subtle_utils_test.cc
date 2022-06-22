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
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-simple/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

struct SphincsUtilsTestCase {
  std::string test_name;
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureType sig_length_type;
  int32_t private_key_size;
  int32_t public_key_size;
};

using SphincsUtilsTest = testing::TestWithParam<SphincsUtilsTestCase>;

TEST_P(SphincsUtilsTest, SphincsKeysLength) {
  const SphincsUtilsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Check keys size.
  EXPECT_EQ(key_pair->GetPrivateKey().GetKey().size(),
            test_case.private_key_size);
  EXPECT_EQ(key_pair->GetPublicKey().GetKey().size(),
            test_case.public_key_size);
}

TEST_P(SphincsUtilsTest, DifferentContent) {
  const SphincsUtilsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Check keys content is different.
  EXPECT_NE(util::SecretDataAsStringView(key_pair->GetPrivateKey().GetKey()),
            key_pair->GetPublicKey().GetKey());
}

TEST(SphincsUtilsTest, InvalidPrivateKeySize) {
  for (int keysize = 0; keysize <= kSphincsPrivateKeySize128; keysize++) {
    if (keysize == kSphincsPrivateKeySize64 ||
        keysize == kSphincsPrivateKeySize96 ||
        keysize == kSphincsPrivateKeySize128) {
      // Valid key size.
      continue;
    }
    EXPECT_FALSE(ValidatePrivateKeySize(keysize).ok());
  }
}

TEST(SphincsUtilsTest, InvalidPublicKeySize) {
  for (int keysize = 0; keysize <= kSphincsPrivateKeySize128; keysize++) {
    if (keysize == kSphincsPublicKeySize32 ||
        keysize == kSphincsPublicKeySize48 ||
        keysize == kSphincsPublicKeySize64) {
      // Valid key size.
      continue;
    }
    EXPECT_FALSE(ValidatePublicKeySize(keysize).ok());
  }
}

TEST_P(SphincsUtilsTest, ValidParams) {
  const SphincsUtilsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  EXPECT_TRUE(ValidateParams(params).ok());
}

TEST(SphincsUtilsTest, InvalidHashType) {
    SphincsParamsPqclean params = {
      .hash_type = SphincsHashType::UNKNOWN_HASH_TYPE,
      .variant = SphincsVariant::ROBUST,
      .sig_length_type = SphincsSignatureType::FAST_SIGNING,
      .private_key_size = kSphincsPrivateKeySize64,
  };

  EXPECT_FALSE(ValidateParams(params).ok());
}

TEST(SphincsUtilsTest, InvalidVariant) {
    SphincsParamsPqclean params = {
      .hash_type = SphincsHashType::HARAKA,
      .variant = SphincsVariant::UNKNOWN_VARIANT,
      .sig_length_type = SphincsSignatureType::FAST_SIGNING,
      .private_key_size = kSphincsPrivateKeySize64,
  };

  EXPECT_FALSE(ValidateParams(params).ok());
}

TEST(SphincsUtilsTest, InvalidSignatureType) {
    SphincsParamsPqclean params = {
      .hash_type = SphincsHashType::HARAKA,
      .variant = SphincsVariant::ROBUST,
      .sig_length_type = SphincsSignatureType::UNKNOWN_SIG_TYPE,
      .private_key_size = kSphincsPrivateKeySize64,
  };

  EXPECT_FALSE(ValidateParams(params).ok());
}

INSTANTIATE_TEST_SUITE_P(
    SphincsUtilsTests, SphincsUtilsTest,
    testing::ValuesIn<SphincsUtilsTestCase>(
        {{"SPHINCSHARAKA128FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA128SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSHARAKA192FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA192SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSHARAKA256FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSHARAKA256SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256128FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256128SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256192FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256192SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHA256256FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHA256256SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256128FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256128SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256192FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256192SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_PUBLICKEYBYTES},

         {"SPHINCSSHAKE256256FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_PUBLICKEYBYTES},
         {"SPHINCSSHAKE256256SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_PUBLICKEYBYTES}}),
    [](const testing::TestParamInfo<SphincsUtilsTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
