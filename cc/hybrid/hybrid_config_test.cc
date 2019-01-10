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
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
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
  std::string aes_eax_key_type =
      "type.googleapis.com/google.crypto.tink.AesEaxKey";
  std::string aes_gcm_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
  std::string xchacha20_poly1305_key_type =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  std::string hmac_key_type =
      "type.googleapis.com/google.crypto.tink.HmacKey";
  auto& config = HybridConfig::Latest();

  EXPECT_EQ(7, HybridConfig::Latest().entry_size());

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
  EXPECT_EQ(decrypt_key_type, config.entry(5).type_url());
  EXPECT_EQ(true, config.entry(5).new_key_allowed());
  EXPECT_EQ(0, config.entry(5).key_manager_version());

  EXPECT_EQ("TinkHybridEncrypt", config.entry(6).catalogue_name());
  EXPECT_EQ("HybridEncrypt", config.entry(6).primitive_name());
  EXPECT_EQ(encrypt_key_type, config.entry(6).type_url());
  EXPECT_EQ(true, config.entry(6).new_key_allowed());
  EXPECT_EQ(0, config.entry(6).key_manager_version());

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
  auto status = HybridConfig::Register();
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

TEST_F(HybridConfigTest, testRegister) {
  std::string key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  // Try on empty registry.
  auto status = Config::Register(HybridConfig::Latest());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());
  auto manager_result = Registry::get_key_manager<HybridEncrypt>(key_type);
  EXPECT_FALSE(manager_result.ok());

  // Register and try again.
  status = HybridConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<HybridEncrypt>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();

  // Try Register() again, should succeed (idempotence).
  status = HybridConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkHybridDecrypt",
                                  new DummyHybridDecryptCatalogue());
  EXPECT_TRUE(status.ok()) << status;
  status = HybridConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

// Tests that the HybridEncrypt and HybridDecrypt wrappers have been properly
// registered and we can wrap primitives.
TEST_F(HybridConfigTest, WrappersRegistered) {
  ASSERT_TRUE(HybridConfig::Register().ok());
  auto private_keyset_handle_result = KeysetHandle::GenerateNew(
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm());
  ASSERT_TRUE(private_keyset_handle_result.ok());

  auto public_keyset_handle_result =
      private_keyset_handle_result.ValueOrDie()->GetPublicKeysetHandle();
  ASSERT_TRUE(public_keyset_handle_result.ok());

  auto private_primitive_set_result =
      private_keyset_handle_result.ValueOrDie()->GetPrimitives<HybridDecrypt>(
          nullptr);
  ASSERT_TRUE(private_primitive_set_result.ok());

  auto public_primitive_set_result =
      public_keyset_handle_result.ValueOrDie()->GetPrimitives<HybridEncrypt>(
          nullptr);
  ASSERT_TRUE(public_primitive_set_result.ok());

  auto private_primitive_result =
      Registry::Wrap(std::move(private_primitive_set_result.ValueOrDie()));
  ASSERT_TRUE(private_primitive_result.ok());

  auto public_primitive_result =
      Registry::Wrap(std::move(public_primitive_set_result.ValueOrDie()));
  ASSERT_TRUE(public_primitive_result.ok());

  auto encryption_result =
      public_primitive_result.ValueOrDie()->Encrypt("encrypted text", "");
  ASSERT_TRUE(encryption_result.ok());

  auto decryption_result = private_primitive_result.ValueOrDie()->Decrypt(
      encryption_result.ValueOrDie(), "");
  ASSERT_TRUE(decryption_result.ok());
  EXPECT_EQ(decryption_result.ValueOrDie(), "encrypted text");
}

}  // namespace
}  // namespace tink
}  // namespace crypto
