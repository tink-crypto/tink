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

#include "tink/experimental/pqcrypto/signature/dilithium_key_template.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"
#include "proto/tink.proto.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium2aes/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3aes/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5aes/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::DilithiumKeyFormat;
using ::google::crypto::tink::DilithiumParams;
using ::google::crypto::tink::DilithiumPrivateKey;
using ::google::crypto::tink::DilithiumSeedExpansion;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

struct DilithiumKeyTemplateTestCase {
  std::string test_name;
  int32 key_size;
  DilithiumSeedExpansion seed_expansion;
  KeyTemplate key_template;
};

using DilithiumKeyTemplateTest =
    testing::TestWithParam<DilithiumKeyTemplateTestCase>;

TEST_P(DilithiumKeyTemplateTest, CheckDilithiumInitialization) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.DilithiumPrivateKey";
  const KeyTemplate& key_template = GetParam().key_template;

  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
}

TEST_P(DilithiumKeyTemplateTest, ValidateKeyFormat) {
  const DilithiumKeyTemplateTestCase& test_case = GetParam();
  DilithiumKeyFormat key_format;

  DilithiumParams* params = key_format.mutable_params();
  params->set_key_size(test_case.key_size);
  params->set_seed_expansion(test_case.seed_expansion);

  EXPECT_THAT(DilithiumSignKeyManager().ValidateKeyFormat(key_format), IsOk());
  EXPECT_TRUE(key_format.ParseFromString(test_case.key_template.value()));
}

TEST_P(DilithiumKeyTemplateTest, SameReference) {
  const KeyTemplate& key_template = GetParam().key_template;
  const KeyTemplate& key_template_2 = GetParam().key_template;

  EXPECT_EQ(&key_template, &key_template_2);
}

TEST_P(DilithiumKeyTemplateTest, KeyManagerCompatibility) {
  DilithiumSignKeyManager sign_key_manager;
  DilithiumVerifyKeyManager verify_key_manager;
  std::unique_ptr<KeyManager<PublicKeySign>> key_manager =
      internal::MakePrivateKeyManager<PublicKeySign>(&sign_key_manager,
                                                     &verify_key_manager);
  DilithiumKeyFormat key_format;
  const DilithiumKeyTemplateTestCase& test_case = GetParam();

  DilithiumParams* params = key_format.mutable_params();
  params->set_key_size(test_case.key_size);
  params->set_seed_expansion(test_case.seed_expansion);

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> new_key_result =
      key_manager->get_key_factory().NewKey(key_format);
  EXPECT_THAT(new_key_result.status(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    DilithiumKeyTemplateTests, DilithiumKeyTemplateTest,
    testing::ValuesIn<DilithiumKeyTemplateTestCase>(
        {{"Dilithium2", PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES,
          DilithiumSeedExpansion::SEED_EXPANSION_SHAKE,
          Dilithium2KeyTemplate()},
         {"Dilithium3", PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES,
          DilithiumSeedExpansion::SEED_EXPANSION_SHAKE,
          Dilithium3KeyTemplate()},
         {"Dilithium5", PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES,
          DilithiumSeedExpansion::SEED_EXPANSION_SHAKE,
          Dilithium5KeyTemplate()},
         {"Dilithium2Aes", PQCLEAN_DILITHIUM2AES_AVX2_CRYPTO_SECRETKEYBYTES,
          DilithiumSeedExpansion::SEED_EXPANSION_AES,
          Dilithium2AesKeyTemplate()},
         {"Dilithium3Aes", PQCLEAN_DILITHIUM3AES_AVX2_CRYPTO_SECRETKEYBYTES,
          DilithiumSeedExpansion::SEED_EXPANSION_AES,
          Dilithium3AesKeyTemplate()},
         {"Dilithium5Aes", PQCLEAN_DILITHIUM5AES_AVX2_CRYPTO_SECRETKEYBYTES,
          DilithiumSeedExpansion::SEED_EXPANSION_AES,
          Dilithium5AesKeyTemplate()}}),
    [](const testing::TestParamInfo<DilithiumKeyTemplateTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace
}  // namespace tink
}  // namespace crypto
