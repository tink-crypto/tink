// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/mac/mac_key_templates.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesCmacKeyFormat;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Ref;

TEST(MacKeyTemplatesTest, testHmacKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.HmacKey";

  {  // Test Hmac128BittagSha256().
    // Check that returned template is correct.
    const KeyTemplate& key_template = MacKeyTemplates::HmacSha256HalfSizeTag();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    HmacKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(32, key_format.key_size());
    EXPECT_EQ(16, key_format.params().tag_size());
    EXPECT_EQ(HashType::SHA256, key_format.params().hash());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 =
        MacKeyTemplates::HmacSha256HalfSizeTag();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    HmacKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Mac>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Hmac256BittagSha256().
    // Check that returned template is correct.
    const KeyTemplate& key_template = MacKeyTemplates::HmacSha256();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    HmacKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(32, key_format.key_size());
    EXPECT_EQ(32, key_format.params().tag_size());
    EXPECT_EQ(HashType::SHA256, key_format.params().hash());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = MacKeyTemplates::HmacSha256();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    HmacKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Mac>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Hmac256BittagSha512().
    // Check that returned template is correct.
    const KeyTemplate& key_template = MacKeyTemplates::HmacSha512HalfSizeTag();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    HmacKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(64, key_format.key_size());
    EXPECT_EQ(32, key_format.params().tag_size());
    EXPECT_EQ(HashType::SHA512, key_format.params().hash());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 =
        MacKeyTemplates::HmacSha512HalfSizeTag();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    HmacKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Mac>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Hmac512BittagSha512().
    // Check that returned template is correct.
    const KeyTemplate& key_template = MacKeyTemplates::HmacSha512();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    HmacKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(64, key_format.key_size());
    EXPECT_EQ(64, key_format.params().tag_size());
    EXPECT_EQ(HashType::SHA512, key_format.params().hash());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = MacKeyTemplates::HmacSha512();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    HmacKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Mac>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(AesCmac, Basics) {
  EXPECT_THAT(MacKeyTemplates::AesCmac().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));
  EXPECT_THAT(MacKeyTemplates::AesCmac().type_url(),
              Eq(AesCmacKeyManager().get_key_type()));
}

TEST(AesCmac, OutputPrefixType) {
  EXPECT_THAT(MacKeyTemplates::AesCmac().output_prefix_type(),
              Eq(OutputPrefixType::TINK));
}

TEST(AesCmac, MultipleCallsSameReference) {
  EXPECT_THAT(MacKeyTemplates::AesCmac(), Ref(MacKeyTemplates::AesCmac()));
}

TEST(AesCmac, WorksWithKeyTypeManager) {
  AesCmacKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(MacKeyTemplates::AesCmac().value()));
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(AesCmac, CheckValues) {
  AesCmacKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(MacKeyTemplates::AesCmac().value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
  EXPECT_THAT(key_format.params().tag_size(), Eq(16));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
