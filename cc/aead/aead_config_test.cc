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

#include "tink/aead/aead_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyAead;
using ::testing::Eq;

class DummyAeadCatalogue : public Catalogue<Aead> {
 public:
  DummyAeadCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<Aead>>> GetKeyManager(
      const std::string& type_url, const std::string& primitive_name,
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
  std::string aes_eax_key_type = "type.googleapis.com/google.crypto.tink.AesEaxKey";
  std::string aes_gcm_key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";
  std::string aes_gcm_siv_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmSivKey";
  std::string xchacha20_poly1305_key_type =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  std::string kms_aead_key_type =
      "type.googleapis.com/google.crypto.tink.KmsAeadKey";
  std::string kms_envelope_aead_key_type =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
  std::string hmac_key_type = "type.googleapis.com/google.crypto.tink.HmacKey";
  auto& config = AeadConfig::Latest();

  EXPECT_EQ(8, AeadConfig::Latest().entry_size());

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
  EXPECT_EQ(aes_gcm_siv_key_type, config.entry(3).type_url());
  EXPECT_EQ(true, config.entry(3).new_key_allowed());
  EXPECT_EQ(0, config.entry(3).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(4).catalogue_name());
  EXPECT_EQ("Aead", config.entry(4).primitive_name());
  EXPECT_EQ(aes_eax_key_type, config.entry(4).type_url());
  EXPECT_EQ(true, config.entry(4).new_key_allowed());
  EXPECT_EQ(0, config.entry(4).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(5).catalogue_name());
  EXPECT_EQ("Aead", config.entry(5).primitive_name());
  EXPECT_EQ(xchacha20_poly1305_key_type, config.entry(5).type_url());
  EXPECT_EQ(true, config.entry(5).new_key_allowed());
  EXPECT_EQ(0, config.entry(5).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(6).catalogue_name());
  EXPECT_EQ("Aead", config.entry(6).primitive_name());
  EXPECT_EQ(kms_aead_key_type, config.entry(6).type_url());
  EXPECT_EQ(true, config.entry(6).new_key_allowed());
  EXPECT_EQ(0, config.entry(6).key_manager_version());

  EXPECT_EQ("TinkAead", config.entry(7).catalogue_name());
  EXPECT_EQ("Aead", config.entry(7).primitive_name());
  EXPECT_EQ(kms_envelope_aead_key_type, config.entry(7).type_url());
  EXPECT_EQ(true, config.entry(7).new_key_allowed());
  EXPECT_EQ(0, config.entry(7).key_manager_version());

  // No key manager before registration.
  auto manager_result = Registry::get_key_manager<Aead>(aes_gcm_key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = AeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<Aead>(aes_gcm_key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(aes_gcm_key_type));
}

TEST_F(AeadConfigTest, testRegister) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";

  // Try on empty registry.
  auto status = Config::Register(AeadConfig::Latest());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());
  auto manager_result = Registry::get_key_manager<Aead>(key_type);
  EXPECT_FALSE(manager_result.ok());

  // Register and try again.
  status = AeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<Aead>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();

  // Try Register() again, should succeed (idempotence).
  status = AeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkAead",
                                  absl::make_unique<DummyAeadCatalogue>());
  EXPECT_TRUE(status.ok()) << status;
  status = AeadConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

// Tests that the AeadWrapper has been properly registered and we can wrap
// primitives.
TEST_F(AeadConfigTest, WrappersRegistered) {
  ASSERT_TRUE(AeadConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<Aead>>();
  primitive_set->set_primary(
      primitive_set->AddPrimitive(absl::make_unique<DummyAead>("dummy"), key)
          .ValueOrDie());

  auto primitive_result = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(primitive_result.ok()) << primitive_result.status();
  auto encryption_result = primitive_result.ValueOrDie()->Encrypt("secret", "");
  ASSERT_TRUE(encryption_result.ok());

  auto decryption_result =
      DummyAead("dummy").Decrypt(encryption_result.ValueOrDie(), "");
  ASSERT_TRUE(decryption_result.status().ok());
  EXPECT_THAT(decryption_result.ValueOrDie(), Eq("secret"));

  decryption_result =
      DummyAead("dummy").Decrypt(encryption_result.ValueOrDie(), "wrog");
  EXPECT_FALSE(decryption_result.status().ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
