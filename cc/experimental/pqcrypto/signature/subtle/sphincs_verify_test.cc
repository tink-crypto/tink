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

#include "tink/experimental/pqcrypto/signature/subtle/sphincs_verify.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_helper_pqclean.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_sign.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
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

struct SphincsTestCase {
  std::string test_name;
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureType sig_length_type;
  int32_t private_key_size;
  int32_t signature_length;
};

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using crypto::tink::util::Status;

using SphincsVerifyTest = testing::TestWithParam<SphincsTestCase>;

TEST_P(SphincsVerifyTest, BasicSignVerify) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SphincsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SphincsSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  Status status = (*verifier)->Verify(*signature, message);
  EXPECT_THAT(status, IsOk());
}

TEST_P(SphincsVerifyTest, FailsWithWrongSignature) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SphincsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SphincsSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  Status status =
      (*verifier)->Verify(*signature + "some trailing data", message);
  EXPECT_FALSE(status.ok());
}

TEST_P(SphincsVerifyTest, FailsWithWrongMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SphincsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SphincsSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  Status status = (*verifier)->Verify(*signature, "some bad message");
  EXPECT_FALSE(status.ok());
}

TEST_P(SphincsVerifyTest, FailsWithBytesFlipped) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SphincsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SphincsSign::New(key_pair->GetPrivateKey());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      SphincsVerify::New(key_pair->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one signature byte.
  (*signature)[0] ^= 1;

  // Verify signature.
  Status status = (*verifier)->Verify(*signature, message);
  EXPECT_FALSE(status.ok());
}

TEST_P(SphincsVerifyTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  const SphincsTestCase& test_case = GetParam();

  SphincsParamsPqclean params = {
      .hash_type = test_case.hash_type,
      .variant = test_case.variant,
      .sig_length_type = test_case.sig_length_type,
      .private_key_size = test_case.private_key_size,
  };

  // Generate sphincs key pair.
  util::StatusOr<SphincsKeyPair> key_pair = GenerateSphincsKeyPair(params);
  ASSERT_THAT(key_pair, IsOk());

  // Create a new signer.
  EXPECT_THAT(SphincsVerify::New(key_pair->GetPublicKey()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

// TODO(ioannanedelcu): Add test with testvectors.

INSTANTIATE_TEST_SUITE_P(
    SphincsVerifyTests, SphincsVerifyTest,
    testing::ValuesIn<SphincsTestCase>(
        {{"SPHINCSHARAKA128FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_BYTES},
         {"SPHINCSHARAKA128SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_BYTES},
         {"SPHINCSHARAKA128FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSHARAKA128SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSHARAKA192FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_BYTES},
         {"SPHINCSHARAKA192SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_BYTES},
         {"SPHINCSHARAKA192FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSHARAKA192SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSHARAKA256FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_BYTES},
         {"SPHINCSHARAKA256SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_BYTES},
         {"SPHINCSHARAKA256FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSHARAKA256SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSSHA256128FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_BYTES},
         {"SPHINCSSHA256128SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_BYTES},
         {"SPHINCSSHA256128FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSSHA256128SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSSHA256192FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_BYTES},
         {"SPHINCSSHA256192SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_BYTES},
         {"SPHINCSSHA256192FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSSHA256192SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSSHA256256FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_BYTES},
         {"SPHINCSSHA256256SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_BYTES},
         {"SPHINCSSHA256256FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSSHA256256SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSSHAKE256128FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_BYTES},
         {"SPHINCSSHAKE256128SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_BYTES},
         {"SPHINCSSHAKE256128FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSSHAKE256128SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSSHAKE256192FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_BYTES},
         {"SPHINCSSHAKE256192SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_BYTES},
         {"SPHINCSSHAKE256192FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSSHAKE256192SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_BYTES},

         {"SPHINCSSHAKE256256FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_BYTES},
         {"SPHINCSSHAKE256256SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_BYTES},
         {"SPHINCSSHAKE256256FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_BYTES},
         {"SPHINCSSHAKE256256SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_SECRETKEYBYTES,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_BYTES}}),
    [](const testing::TestParamInfo<SphincsVerifyTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
