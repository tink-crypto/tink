// Copyright 2017 Google Inc.
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

#include "tink/daead/deterministic_aead_config.h"

#include <list>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/deterministic_aead.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyDeterministicAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

class DeterministicAeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(DeterministicAeadConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<DeterministicAead>(
                  AesSivKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(DeterministicAeadConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<DeterministicAead>(
                  AesSivKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the DeterministicAeadWrapper has been properly registered and we
// can wrap primitives.
TEST_F(DeterministicAeadConfigTest, WrappersRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(DeterministicAeadConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<DeterministicAead>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("dummy"),
                             key_info)
              .ValueOrDie()),
      IsOk());

  auto registry_wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(registry_wrapped.ok()) << registry_wrapped.status();
  auto encryption_result =
      registry_wrapped.ValueOrDie()->EncryptDeterministically("secret", "");
  ASSERT_TRUE(encryption_result.ok());

  auto decryption_result =
      DummyDeterministicAead("dummy").DecryptDeterministically(
          encryption_result.ValueOrDie(), "");
  ASSERT_TRUE(decryption_result.status().ok());
  EXPECT_THAT(decryption_result.ValueOrDie(), Eq("secret"));

  decryption_result = DummyDeterministicAead("dummy").DecryptDeterministically(
      encryption_result.ValueOrDie(), "wrong");
  EXPECT_FALSE(decryption_result.status().ok());
}

TEST_F(DeterministicAeadConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(DeterministicAeadConfig::Register(), IsOk());

  // Check that we can not retrieve non-FIPS key handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(DeterministicAeadKeyTemplates::Aes256Siv());

  for (auto key_template : non_fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result.status(),
               StatusIs(absl::StatusCode::kNotFound));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
