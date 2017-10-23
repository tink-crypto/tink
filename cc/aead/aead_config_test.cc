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

#include "cc/aead/aead_config.h"

#include "cc/aead.h"
#include "cc/catalogue.h"
#include "cc/config.h"
#include "cc/registry.h"
#include "cc/util/status.h"
#include "gtest/gtest.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {
namespace {

class DummyAeadCatalogue : public Catalogue<Aead> {
 public:
  DummyAeadCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<Aead>>> GetKeyManager(
      const std::string& type_url,
      const std::string& primitive_name,
      uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};

class AeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(AeadConfigTest, testBasic) {
  std::string aes_ctr_hmac_aead_key_type =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  std::string aes_gcm_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
  std::string hmac_key_type = "type.googleapis.com/google.crypto.tink.HmacKey";
  auto& config = AeadConfig::Tink_1_1_0();

  EXPECT_EQ(3, AeadConfig::Tink_1_1_0().entry_size());

  EXPECT_EQ("TinkMac", config.entry(0).catalogue_name());
  EXPECT_EQ("Mac", config.entry(0).primitive_name());
  EXPECT_EQ(hmac_key_type, config.entry(0).type_url());
  EXPECT_EQ(true, config.entry(0).new_key_allowed());
  EXPECT_EQ(0, config.entry(0).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(1).catalogue_name());
  EXPECT_EQ("Aead", config.entry(1).primitive_name());
  EXPECT_EQ(aes_ctr_hmac_aead_key_type, config.entry(1).type_url());
  EXPECT_EQ(true, config.entry(1).new_key_allowed());
  EXPECT_EQ(0, config.entry(1).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(2).catalogue_name());
  EXPECT_EQ("Aead", config.entry(2).primitive_name());
  EXPECT_EQ(aes_gcm_key_type, config.entry(2).type_url());
  EXPECT_EQ(true, config.entry(2).new_key_allowed());
  EXPECT_EQ(0, config.entry(2).key_manager_version());

  // No key manager before registration.
  auto manager_result = Registry::get_key_manager<Aead>(aes_gcm_key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = AeadConfig::Init();
  EXPECT_TRUE(status.ok()) << status;
  status = Config::Register(AeadConfig::Tink_1_1_0());
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<Aead>(aes_gcm_key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(aes_gcm_key_type));
}

TEST_F(AeadConfigTest, testInit) {
  // Try on empty registry.
  auto status = Config::Register(AeadConfig::Tink_1_1_0());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());

  // Initialize with a catalogue.
  status = AeadConfig::Init();
  EXPECT_TRUE(status.ok()) << status;
  status = Config::Register(AeadConfig::Tink_1_1_0());
  EXPECT_TRUE(status.ok()) << status;

  // Try Init() again, should succeed (idempotence).
  status = AeadConfig::Init();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkAead", new DummyAeadCatalogue());
  EXPECT_TRUE(status.ok()) << status;
  status = AeadConfig::Init();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

TEST_F(AeadConfigTest, testDeprecated) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";

  // Registration of standard key types works.
  auto status = AeadConfig::RegisterStandardKeyTypes();
  EXPECT_TRUE(status.ok()) << status;
  auto manager_result = Registry::get_key_manager<Aead>(key_type);
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
