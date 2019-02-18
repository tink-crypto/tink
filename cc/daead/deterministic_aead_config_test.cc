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
#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/deterministic_aead.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyDeterministicAead;
using ::testing::Eq;

class DummyDaeadCatalogue : public Catalogue<DeterministicAead> {
 public:
  DummyDaeadCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<DeterministicAead>>>
  GetKeyManager(const std::string& type_url, const std::string& primitive_name,
                uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};

class DeterministicAeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(DeterministicAeadConfigTest, testBasic) {
  std::string aes_siv_key_type = "type.googleapis.com/google.crypto.tink.AesSivKey";
  auto& config = DeterministicAeadConfig::Latest();

  EXPECT_EQ(1, DeterministicAeadConfig::Latest().entry_size());

  EXPECT_EQ("TinkDeterministicAead", config.entry(0).catalogue_name());
  EXPECT_EQ("DeterministicAead", config.entry(0).primitive_name());
  EXPECT_EQ(aes_siv_key_type, config.entry(0).type_url());
  EXPECT_EQ(true, config.entry(0).new_key_allowed());
  EXPECT_EQ(0, config.entry(0).key_manager_version());

  // No key manager before registration.
  auto manager_result =
      Registry::get_key_manager<DeterministicAead>(aes_siv_key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = DeterministicAeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result =
      Registry::get_key_manager<DeterministicAead>(aes_siv_key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(aes_siv_key_type));
}

TEST_F(DeterministicAeadConfigTest, testRegister) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.AesSivKey";

  // Try on empty registry.
  auto status = Config::Register(DeterministicAeadConfig::Latest());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());
  auto manager_result = Registry::get_key_manager<DeterministicAead>(key_type);
  EXPECT_FALSE(manager_result.ok());

  // Register and try again.
  status = DeterministicAeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<DeterministicAead>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();

  // Try Register() again, should succeed (idempotence).
  status = DeterministicAeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkDeterministicAead",
                                  absl::make_unique<DummyDaeadCatalogue>());
  EXPECT_TRUE(status.ok()) << status;
  status = DeterministicAeadConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
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
  primitive_set->set_primary(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("dummy"),
                         key)
          .ValueOrDie());

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
