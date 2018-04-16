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

#include "tink/hybrid/hybrid_config.h"

#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "gtest/gtest.h"


namespace crypto {
namespace tink {
namespace {

class DummyHybridDecryptCatalogue : public Catalogue<HybridDecrypt> {
 public:
  DummyHybridDecryptCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<HybridDecrypt>>>
  GetKeyManager(const std::string& type_url,
                const std::string& primitive_name,
                uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};


class HybridConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }
};

TEST_F(HybridConfigTest, testBasic) {
  std::string decrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  std::string encrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  std::string aes_ctr_hmac_aead_key_type =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  std::string aes_gcm_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
  std::string hmac_key_type =
      "type.googleapis.com/google.crypto.tink.HmacKey";
  auto& config = HybridConfig::Tink_1_1_0();

  EXPECT_EQ(5, HybridConfig::Tink_1_1_0().entry_size());

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

  EXPECT_EQ("TinkHybridDecrypt", config.entry(3).catalogue_name());
  EXPECT_EQ("HybridDecrypt", config.entry(3).primitive_name());
  EXPECT_EQ(decrypt_key_type, config.entry(3).type_url());
  EXPECT_EQ(true, config.entry(3).new_key_allowed());
  EXPECT_EQ(0, config.entry(3).key_manager_version());

  EXPECT_EQ("TinkHybridEncrypt", config.entry(4).catalogue_name());
  EXPECT_EQ("HybridEncrypt", config.entry(4).primitive_name());
  EXPECT_EQ(encrypt_key_type, config.entry(4).type_url());
  EXPECT_EQ(true, config.entry(4).new_key_allowed());
  EXPECT_EQ(0, config.entry(4).key_manager_version());

  // No key manager before registration.
  auto decrypt_manager_result =
      Registry::get_key_manager<HybridDecrypt>(decrypt_key_type);
  EXPECT_FALSE(decrypt_manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND,
            decrypt_manager_result.status().error_code());

  auto encrypt_manager_result =
      Registry::get_key_manager<HybridEncrypt>(encrypt_key_type);
  EXPECT_FALSE(encrypt_manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND,
            encrypt_manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = HybridConfig::Init();
  EXPECT_TRUE(status.ok()) << status;
  status = Config::Register(HybridConfig::Tink_1_1_0());
  EXPECT_TRUE(status.ok()) << status;
  decrypt_manager_result =
      Registry::get_key_manager<HybridDecrypt>(decrypt_key_type);
  EXPECT_TRUE(decrypt_manager_result.ok()) << decrypt_manager_result.status();
  EXPECT_TRUE(decrypt_manager_result.ValueOrDie()
              ->DoesSupport(decrypt_key_type));
  encrypt_manager_result =
      Registry::get_key_manager<HybridEncrypt>(encrypt_key_type);
  EXPECT_TRUE(encrypt_manager_result.ok()) << encrypt_manager_result.status();
  EXPECT_TRUE(encrypt_manager_result.ValueOrDie()
              ->DoesSupport(encrypt_key_type));
}

TEST_F(HybridConfigTest, testInit) {
  // Try on empty registry.
  auto status = Config::Register(HybridConfig::Tink_1_1_0());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());

  // Initialize with a catalogue.
  status = HybridConfig::Init();
  EXPECT_TRUE(status.ok()) << status;
  status = Config::Register(HybridConfig::Tink_1_1_0());
  EXPECT_TRUE(status.ok()) << status;

  // Try Init() again, should succeed (idempotence).
  status = HybridConfig::Init();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkHybridDecrypt",
                                  new DummyHybridDecryptCatalogue());
  EXPECT_TRUE(status.ok()) << status;
  status = HybridConfig::Init();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
