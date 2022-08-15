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

#include "tink/experimental/pqcrypto/signature/sphincs_sign_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_verify.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
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
namespace {

using ::crypto::tink::subtle::SphincsPublicKeyPqclean;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::EnumsPqcrypto;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::SphincsHashType;
using ::google::crypto::tink::SphincsKeyFormat;
using ::google::crypto::tink::SphincsParams;
using ::google::crypto::tink::SphincsPrivateKey;
using ::google::crypto::tink::SphincsPublicKey;
using ::google::crypto::tink::SphincsSignatureType;
using ::google::crypto::tink::SphincsVariant;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

struct SphincsTestCase {
  std::string test_name;
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureType sig_length_type;
  int32_t private_key_size;
  int32_t public_key_size;
};

using SphincsSignKeyManagerTest = testing::TestWithParam<SphincsTestCase>;

// Helper function that returns a valid sphincs key format.
StatusOr<SphincsKeyFormat> CreateValidKeyFormat(int32 private_key_size,
                                                SphincsHashType hash_type,
                                                SphincsVariant variant,
                                                SphincsSignatureType type) {
  SphincsKeyFormat key_format;
  SphincsParams* params = key_format.mutable_params();
  params->set_key_size(private_key_size);
  params->set_hash_type(hash_type);
  params->set_variant(variant);
  params->set_sig_length_type(type);

  return key_format;
}

TEST(SphincsSignKeyManagerTest, Basic) {
  EXPECT_THAT(SphincsSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(SphincsSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(SphincsSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.SphincsPrivateKey"));
}

TEST_P(SphincsSignKeyManagerTest, ValidKeyFormat) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  EXPECT_THAT(SphincsSignKeyManager().ValidateKeyFormat(*key_format), IsOk());
}

TEST(SphincsSignKeyManagerTest, InvalidKeyFormat) {
  StatusOr<SphincsKeyFormat> key_format = CreateValidKeyFormat(
      subtle::kSphincsPrivateKeySize64, SphincsHashType::HASH_TYPE_UNSPECIFIED,
      SphincsVariant::VARIANT_UNSPECIFIED,
      SphincsSignatureType::SIG_TYPE_UNSPECIFIED);
  ASSERT_THAT(key_format, IsOk());

  EXPECT_THAT(SphincsSignKeyManager().ValidateKeyFormat(*key_format),
              Not(IsOk()));
}

TEST_P(SphincsSignKeyManagerTest, CreateKeyValid) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<SphincsPrivateKey> private_key =
      SphincsSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(SphincsSignKeyManager().ValidateKey(*private_key), IsOk());
  EXPECT_THAT(private_key->version(), Eq(0));
  EXPECT_THAT(private_key->public_key().version(), Eq(private_key->version()));
  EXPECT_THAT(private_key->key_value(), SizeIs(test_case.private_key_size));
}

TEST_P(SphincsSignKeyManagerTest, PrivateKeyWrongVersion) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<SphincsPrivateKey> private_key =
      SphincsSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  private_key->set_version(1);
  EXPECT_THAT(SphincsSignKeyManager().ValidateKey(*private_key), Not(IsOk()));
}

TEST(SphincsSignKeyManagerTest, CreateKeyInvalidParams) {
  StatusOr<SphincsKeyFormat> key_format = CreateValidKeyFormat(
      subtle::kSphincsPrivateKeySize64, SphincsHashType::HASH_TYPE_UNSPECIFIED,
      SphincsVariant::VARIANT_UNSPECIFIED,
      SphincsSignatureType::SIG_TYPE_UNSPECIFIED);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<SphincsPrivateKey> private_key =
      SphincsSignKeyManager().CreateKey(*key_format);
  EXPECT_THAT(private_key, Not(IsOk()));
}

TEST_P(SphincsSignKeyManagerTest, CreateKeyAlwaysNew) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  absl::flat_hash_set<std::string> keys;
  int num_tests = 5;
  for (int i = 0; i < num_tests; ++i) {
    StatusOr<SphincsPrivateKey> private_key =
        SphincsSignKeyManager().CreateKey(*key_format);
    ASSERT_THAT(private_key, IsOk());
    keys.insert(private_key->key_value());
  }
  EXPECT_THAT(keys, SizeIs(num_tests));
}

TEST_P(SphincsSignKeyManagerTest, GetPublicKey) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  StatusOr<SphincsPrivateKey> private_key =
      SphincsSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  StatusOr<SphincsPublicKey> public_key_or =
      SphincsSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key_or, IsOk());

  EXPECT_THAT(public_key_or->version(),
              Eq(private_key->public_key().version()));
  EXPECT_THAT(public_key_or->key_value(),
              Eq(private_key->public_key().key_value()));
}

TEST_P(SphincsSignKeyManagerTest, CreateValid) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  util::StatusOr<SphincsPrivateKey> private_key =
      SphincsSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SphincsSignKeyManager().GetPrimitive<PublicKeySign>(*private_key);
  ASSERT_THAT(signer, IsOk());

  subtle::SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type = EnumsPqcrypto::ProtoToSubtle(test_case.hash_type),
      .variant = EnumsPqcrypto::ProtoToSubtle(test_case.variant),
      .sig_length_type =
          EnumsPqcrypto::ProtoToSubtle(test_case.sig_length_type),
      .private_key_size = test_case.private_key_size};

  SphincsPublicKeyPqclean sphincs_public_key_pqclean(
      private_key->public_key().key_value(), sphincs_params_pqclean);

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      subtle::SphincsVerify::New(sphincs_public_key_pqclean);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(SphincsSignKeyManagerTest, CreateBadPublicKey) {
  const SphincsTestCase& test_case = GetParam();

  StatusOr<SphincsKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size, test_case.hash_type,
                           test_case.variant, test_case.sig_length_type);
  ASSERT_THAT(key_format, IsOk());

  util::StatusOr<SphincsPrivateKey> private_key =
      SphincsSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      SphincsSignKeyManager().GetPrimitive<PublicKeySign>(*private_key);
  ASSERT_THAT(signer, IsOk());

  std::string bad_public_key_data(test_case.public_key_size, '@');

  subtle::SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type = EnumsPqcrypto::ProtoToSubtle(test_case.hash_type),
      .variant = EnumsPqcrypto::ProtoToSubtle(test_case.variant),
      .sig_length_type =
          EnumsPqcrypto::ProtoToSubtle(test_case.sig_length_type),
      .private_key_size = test_case.private_key_size};

  SphincsPublicKeyPqclean sphincs_public_key_pqclean(bad_public_key_data,
                                                     sphincs_params_pqclean);
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> direct_verifier =
      subtle::SphincsVerify::New(sphincs_public_key_pqclean);
  ASSERT_THAT(direct_verifier, IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    SphincsSignKeyManagerTests, SphincsSignKeyManagerTest,
    testing::ValuesIn<SphincsTestCase>(
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
    [](const testing::TestParamInfo<SphincsSignKeyManagerTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace

}  // namespace tink
}  // namespace crypto
