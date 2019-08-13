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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/config.h"
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
  EXPECT_THAT(Registry::get_key_manager<DeterministicAead>(
                  AesSivKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(DeterministicAeadConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<DeterministicAead>(
                  AesSivKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the DeterministicAeadWrapper has been properly registered and we
// can wrap primitives.
TEST_F(DeterministicAeadConfigTest, WrappersRegistered) {
  ASSERT_TRUE(DeterministicAeadConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<DeterministicAead>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("dummy"),
                             key)
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
      encryption_result.ValueOrDie(), "wrog");
  EXPECT_FALSE(decryption_result.status().ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
