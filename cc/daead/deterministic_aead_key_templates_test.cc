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

#include "tink/daead/deterministic_aead_key_templates.h"

#include <string>

#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesSivKeyFormat;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(DeterministicAeadKeyTemplatesTest, testAesSivKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.AesSivKey";

  {  // Test Aes256Siv().
    // Check that returned template is correct.
    const KeyTemplate& key_template =
        DeterministicAeadKeyTemplates::Aes256Siv();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesSivKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(64, key_format.key_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 =
        DeterministicAeadKeyTemplates::Aes256Siv();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesSivKeyManager key_type_manager;
    auto key_manager =
        internal::MakeKeyManager<DeterministicAead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
