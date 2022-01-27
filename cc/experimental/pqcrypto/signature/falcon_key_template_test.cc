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

#include "tink/experimental/pqcrypto/signature/falcon_key_template.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/experimental/pqcrypto/signature/falcon_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/falcon_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"
#include "proto/tink.proto.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::FalconKeyFormat;
using ::google::crypto::tink::FalconPrivateKey;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

struct FalconTestCase {
  std::string test_name;
  int32_t private_key_size;
  KeyTemplate key_template;
};

using FalconKeyTemplateTest = testing::TestWithParam<FalconTestCase>;

TEST_P(FalconKeyTemplateTest, CheckKeyTemplateValid) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.FalconPrivateKey";

  const FalconTestCase& test_case = GetParam();
  EXPECT_EQ(type_url, test_case.key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK,
            test_case.key_template.output_prefix_type());

  FalconKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(test_case.key_template.value()));
  EXPECT_EQ(test_case.private_key_size, key_format.key_size());
}

TEST_P(FalconKeyTemplateTest, SameReference) {
  const KeyTemplate& key_template = GetParam().key_template;
  const KeyTemplate& key_template_2 = GetParam().key_template;

  EXPECT_EQ(&key_template, &key_template_2);
}

TEST_P(FalconKeyTemplateTest, KeyManagerCompatibility) {
  FalconSignKeyManager sign_key_manager;
  FalconVerifyKeyManager verify_key_manager;
  std::unique_ptr<KeyManager<PublicKeySign>> key_manager =
      internal::MakePrivateKeyManager<PublicKeySign>(&sign_key_manager,
                                                     &verify_key_manager);
  FalconKeyFormat key_format;
  const FalconTestCase& test_case = GetParam();
  key_format.set_key_size(test_case.private_key_size);

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> new_key_result =
      key_manager->get_key_factory().NewKey(key_format);
  EXPECT_THAT(new_key_result.status(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    FalconKeyTemplateTests, FalconKeyTemplateTest,
    testing::ValuesIn<FalconTestCase>(
        {{"Falcon512", subtle::kFalcon512PrivateKeySize,
          Falcon512KeyTemplate()},
         {"Falcon1024", subtle::kFalcon1024PrivateKeySize,
          Falcon1024KeyTemplate()}}),
    [](const testing::TestParamInfo<FalconKeyTemplateTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace

}  // namespace tink
}  // namespace crypto
