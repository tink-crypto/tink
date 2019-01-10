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

#include "tink/config/tink_config.h"

#include "tink/aead.h"
#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/deterministic_aead.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/mac.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
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


class TinkConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }
};

TEST_F(TinkConfigTest, testBasic) {
  std::string public_key_sign_key_type =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  std::string public_key_verify_key_type =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  std::string hybrid_decrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  std::string hybrid_encrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  std::string aes_ctr_hmac_aead_key_type =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  std::string aes_eax_key_type =
      "type.googleapis.com/google.crypto.tink.AesEaxKey";
  std::string aes_gcm_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
  std::string xchacha20_poly1305_key_type =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  std::string hmac_key_type =
      "type.googleapis.com/google.crypto.tink.HmacKey";
  std::string aes_siv_key_type =
      "type.googleapis.com/google.crypto.tink.AesSivKey";
  auto& config = TinkConfig::Latest();

  EXPECT_EQ(10, TinkConfig::Latest().entry_size());

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

  EXPECT_EQ("TinkAead", config.entry(3).catalogue_name());
  EXPECT_EQ("Aead", config.entry(3).primitive_name());
  EXPECT_EQ(aes_eax_key_type, config.entry(3).type_url());
  EXPECT_EQ(true, config.entry(3).new_key_allowed());
  EXPECT_EQ(0, config.entry(3).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(4).catalogue_name());
  EXPECT_EQ("Aead", config.entry(4).primitive_name());
  EXPECT_EQ(xchacha20_poly1305_key_type, config.entry(4).type_url());
  EXPECT_EQ(true, config.entry(4).new_key_allowed());
  EXPECT_EQ(0, config.entry(4).key_manager_version());

  EXPECT_EQ("TinkHybridDecrypt", config.entry(5).catalogue_name());
  EXPECT_EQ("HybridDecrypt", config.entry(5).primitive_name());
  EXPECT_EQ(hybrid_decrypt_key_type, config.entry(5).type_url());
  EXPECT_EQ(true, config.entry(5).new_key_allowed());
  EXPECT_EQ(0, config.entry(5).key_manager_version());

  EXPECT_EQ("TinkHybridEncrypt", config.entry(6).catalogue_name());
  EXPECT_EQ("HybridEncrypt", config.entry(6).primitive_name());
  EXPECT_EQ(hybrid_encrypt_key_type, config.entry(6).type_url());
  EXPECT_EQ(true, config.entry(6).new_key_allowed());
  EXPECT_EQ(0, config.entry(6).key_manager_version());

  EXPECT_EQ("TinkPublicKeySign", config.entry(7).catalogue_name());
  EXPECT_EQ("PublicKeySign", config.entry(7).primitive_name());
  EXPECT_EQ(public_key_sign_key_type, config.entry(7).type_url());
  EXPECT_EQ(true, config.entry(7).new_key_allowed());
  EXPECT_EQ(0, config.entry(7).key_manager_version());

  EXPECT_EQ("TinkPublicKeyVerify", config.entry(8).catalogue_name());
  EXPECT_EQ("PublicKeyVerify", config.entry(8).primitive_name());
  EXPECT_EQ(public_key_verify_key_type, config.entry(8).type_url());
  EXPECT_EQ(true, config.entry(8).new_key_allowed());
  EXPECT_EQ(0, config.entry(8).key_manager_version());

  EXPECT_EQ("TinkDeterministicAead", config.entry(9).catalogue_name());
  EXPECT_EQ("DeterministicAead", config.entry(9).primitive_name());
  EXPECT_EQ(aes_siv_key_type, config.entry(9).type_url());
  EXPECT_EQ(true, config.entry(9).new_key_allowed());
  EXPECT_EQ(0, config.entry(9).key_manager_version());

  // No key manager before registration.
  {
    auto manager_result = Registry::get_key_manager<Aead>(aes_gcm_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  {
    auto manager_result = Registry::get_key_manager<Mac>(hmac_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  {
    auto manager_result =
        Registry::get_key_manager<HybridEncrypt>(hybrid_encrypt_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  {
    auto manager_result =
        Registry::get_key_manager<HybridDecrypt>(hybrid_decrypt_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  {
    auto manager_result =
        Registry::get_key_manager<PublicKeySign>(public_key_sign_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  {
    auto manager_result =
        Registry::get_key_manager<PublicKeyVerify>(public_key_verify_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  {
    auto manager_result =
        Registry::get_key_manager<DeterministicAead>(aes_siv_key_type);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }

  // Registration of standard key types works.
  auto status = TinkConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  {
    auto manager_result = Registry::get_key_manager<Aead>(aes_gcm_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(aes_gcm_key_type));
  }
  {
    auto manager_result = Registry::get_key_manager<Mac>(hmac_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(hmac_key_type));
  }
  {
    auto manager_result =
        Registry::get_key_manager<HybridEncrypt>(hybrid_encrypt_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(
        hybrid_encrypt_key_type));
  }
  {
    auto manager_result =
        Registry::get_key_manager<HybridDecrypt>(hybrid_decrypt_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(
        hybrid_decrypt_key_type));
  }
  {
    auto manager_result =
        Registry::get_key_manager<PublicKeySign>(public_key_sign_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(
        public_key_sign_key_type));
  }
  {
    auto manager_result =
        Registry::get_key_manager<PublicKeyVerify>(public_key_verify_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(
        public_key_verify_key_type));
  }
  {
    auto manager_result =
        Registry::get_key_manager<DeterministicAead>(aes_siv_key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(aes_siv_key_type));
  }
}

TEST_F(TinkConfigTest, testRegister) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";

  // Try on empty registry.
  auto status = Config::Register(TinkConfig::Latest());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());
  auto manager_result = Registry::get_key_manager<Aead>(key_type);
  EXPECT_FALSE(manager_result.ok());

  // Register and try again.
  status = TinkConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<Aead>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();

  // Try Register() again, should succeed (idempotence).
  status = TinkConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkHybridDecrypt",
                                  new DummyHybridDecryptCatalogue());
  EXPECT_TRUE(status.ok()) << status;
  status = TinkConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
