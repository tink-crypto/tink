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

#include "tink/experimental/pqcrypto/signature/sphincs_key_template.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/experimental/pqcrypto/signature/sphincs_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

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

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::SphincsHashType;
using ::google::crypto::tink::SphincsKeyFormat;
using ::google::crypto::tink::SphincsParams;
using ::google::crypto::tink::SphincsPrivateKey;
using ::google::crypto::tink::SphincsSignatureType;
using ::google::crypto::tink::SphincsVariant;

struct SphincsTestCase {
  std::string test_name;
  SphincsHashType hash_type;
  SphincsVariant variant;
  SphincsSignatureType sig_length_type;
  int32_t private_key_size;
  KeyTemplate key_template;
};

using SphincsKeyTemplateTest = testing::TestWithParam<SphincsTestCase>;

TEST_P(SphincsKeyTemplateTest, CheckKeyTemplateValid) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.SphincsPrivateKey";

  const SphincsTestCase& test_case = GetParam();
  EXPECT_EQ(type_url, test_case.key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK,
            test_case.key_template.output_prefix_type());

  SphincsKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(test_case.key_template.value()));
  EXPECT_EQ(test_case.hash_type, key_format.params().hash_type());
  EXPECT_EQ(test_case.variant, key_format.params().variant());
  EXPECT_EQ(test_case.sig_length_type, key_format.params().sig_length_type());
  EXPECT_EQ(test_case.private_key_size, key_format.params().key_size());
}

TEST_P(SphincsKeyTemplateTest, SameReference) {
  const KeyTemplate& key_template = GetParam().key_template;
  const KeyTemplate& key_template_2 = GetParam().key_template;

  EXPECT_EQ(&key_template, &key_template_2);
}

TEST_P(SphincsKeyTemplateTest, KeyManagerCompatibility) {
  SphincsSignKeyManager sign_key_manager;
  SphincsVerifyKeyManager verify_key_manager;
  std::unique_ptr<KeyManager<PublicKeySign>> key_manager =
      internal::MakePrivateKeyManager<PublicKeySign>(&sign_key_manager,
                                                     &verify_key_manager);
  SphincsKeyFormat key_format;
  const SphincsTestCase& test_case = GetParam();

  SphincsParams* params = key_format.mutable_params();
  params->set_key_size(test_case.private_key_size);
  params->set_hash_type(test_case.hash_type);
  params->set_variant(test_case.variant);
  params->set_sig_length_type(test_case.sig_length_type);

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> new_key_result =
      key_manager->get_key_factory().NewKey(key_format);
  EXPECT_THAT(new_key_result.status(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    SphincsKeyTemplateTests, SphincsKeyTemplateTest,
    testing::ValuesIn<SphincsTestCase>(
        {{"SPHINCSHARAKA128FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_128_F_Robust_KeyTemplate()},
         {"SPHINCSHARAKA128SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_128_S_Robust_KeyTemplate()},
         {"SPHINCSHARAKA128FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA128FSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_128_F_Simple_KeyTemplate()},
         {"SPHINCSHARAKA128SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA128SSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_128_S_Simple_KeyTemplate()},

         {"SPHINCSHARAKA192FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_192_F_Robust_KeyTemplate()},
         {"SPHINCSHARAKA192SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_192_S_Robust_KeyTemplate()},
         {"SPHINCSHARAKA192FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA192FSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_192_F_Simple_KeyTemplate()},
         {"SPHINCSHARAKA192SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA192SSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_192_S_Simple_KeyTemplate()},

         {"SPHINCSHARAKA256FROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_256_F_Robust_KeyTemplate()},
         {"SPHINCSHARAKA256SROBUST", SphincsHashType::HARAKA,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SROBUST_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_256_S_Robust_KeyTemplate()},
         {"SPHINCSHARAKA256FSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSHARAKA256FSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_256_F_Simple_KeyTemplate()},
         {"SPHINCSHARAKA256SSIMPLE", SphincsHashType::HARAKA,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSHARAKA256SSIMPLE_AESNI_CRYPTO_SECRETKEYBYTES,
          Sphincs_Haraka_256_S_Simple_KeyTemplate()},

         {"SPHINCSSHA256128FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_128_F_Robust_KeyTemplate()},
         {"SPHINCSSHA256128SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_128_S_Robust_KeyTemplate()},
         {"SPHINCSSHA256128FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_128_F_Simple_KeyTemplate()},
         {"SPHINCSSHA256128SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_128_S_Simple_KeyTemplate()},

         {"SPHINCSSHA256192FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_192_F_Robust_KeyTemplate()},
         {"SPHINCSSHA256192SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_192_S_Robust_KeyTemplate()},
         {"SPHINCSSHA256192FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_192_F_Simple_KeyTemplate()},
         {"SPHINCSSHA256192SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_192_S_Simple_KeyTemplate()},

         {"SPHINCSSHA256256FROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_256_F_Robust_KeyTemplate()},
         {"SPHINCSSHA256256SROBUST", SphincsHashType::SHA256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_256_S_Robust_KeyTemplate()},
         {"SPHINCSSHA256256FSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHA256256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_256_F_Simple_KeyTemplate()},
         {"SPHINCSSHA256256SSIMPLE", SphincsHashType::SHA256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHA256256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Sha256_256_S_Simple_KeyTemplate()},

         {"SPHINCSSHAKE256128FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_128_F_Robust_KeyTemplate()},
         {"SPHINCSSHAKE256128SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_128_S_Robust_KeyTemplate()},
         {"SPHINCSSHAKE256128FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256128FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_128_F_Simple_KeyTemplate()},
         {"SPHINCSSHAKE256128SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256128SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_128_S_Simple_KeyTemplate()},

         {"SPHINCSSHAKE256192FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_192_F_Robust_KeyTemplate()},
         {"SPHINCSSHAKE256192SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_192_S_Robust_KeyTemplate()},
         {"SPHINCSSHAKE256192FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256192FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_192_F_Simple_KeyTemplate()},
         {"SPHINCSSHAKE256192SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256192SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_192_S_Simple_KeyTemplate()},

         {"SPHINCSSHAKE256256FROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_256_F_Robust_KeyTemplate()},
         {"SPHINCSSHAKE256256SROBUST", SphincsHashType::SHAKE256,
          SphincsVariant::ROBUST, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SROBUST_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_256_S_Robust_KeyTemplate()},
         {"SPHINCSSHAKE256256FSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::FAST_SIGNING,
          PQCLEAN_SPHINCSSHAKE256256FSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_256_F_Simple_KeyTemplate()},
         {"SPHINCSSHAKE256256SSIMPLE", SphincsHashType::SHAKE256,
          SphincsVariant::SIMPLE, SphincsSignatureType::SMALL_SIGNATURE,
          PQCLEAN_SPHINCSSHAKE256256SSIMPLE_AVX2_CRYPTO_SECRETKEYBYTES,
          Sphincs_Shake256_256_S_Simple_KeyTemplate()}}),
    [](const testing::TestParamInfo<SphincsKeyTemplateTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace tink
}  // namespace crypto
