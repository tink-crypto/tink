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

#include "tink/mac/mac_config.h"

#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/mac.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "gtest/gtest.h"


namespace crypto {
namespace tink {
namespace {

class DummyMacCatalogue : public Catalogue<Mac> {
 public:
  DummyMacCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<Mac>>>
  GetKeyManager(const std::string& type_url,
                const std::string& primitive_name,
                uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};


class MacConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }
};

TEST_F(MacConfigTest, testBasic) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.HmacKey";
  auto& config = MacConfig::Tink_1_1_0();

  EXPECT_EQ(1, MacConfig::Tink_1_1_0().entry_size());
  EXPECT_EQ("TinkMac", config.entry(0).catalogue_name());
  EXPECT_EQ("Mac", config.entry(0).primitive_name());
  EXPECT_EQ(key_type, config.entry(0).type_url());
  EXPECT_EQ(true, config.entry(0).new_key_allowed());
  EXPECT_EQ(0, config.entry(0).key_manager_version());

  // No key manager before registration.
  auto manager_result = Registry::get_key_manager<Mac>(key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = MacConfig::Init();
  EXPECT_TRUE(status.ok()) << status;
  status = Config::Register(MacConfig::Tink_1_1_0());
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<Mac>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(key_type));
}

TEST_F(MacConfigTest, testInit) {
  // Try on empty registry.
  auto status = Config::Register(MacConfig::Tink_1_1_0());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());

  // Initialize with a catalogue.
  status = MacConfig::Init();
  EXPECT_TRUE(status.ok()) << status;
  status = Config::Register(MacConfig::Tink_1_1_0());
  EXPECT_TRUE(status.ok()) << status;

  // Try Init() again, should succeed (idempotence).
  status = MacConfig::Init();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkMac", new DummyMacCatalogue());
  EXPECT_TRUE(status.ok()) << status;
  status = MacConfig::Init();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

TEST_F(MacConfigTest, testDeprecated) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.HmacKey";

  // Registration of standard key types works.
  auto status = MacConfig::RegisterStandardKeyTypes();
  EXPECT_TRUE(status.ok()) << status;
  auto manager_result = Registry::get_key_manager<Mac>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(key_type));
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
