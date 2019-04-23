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

#include "gtest/gtest.h"
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
#include "tink/streaming_aead.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace {

class DummyHybridDecryptCatalogue : public Catalogue<HybridDecrypt> {
 public:
  DummyHybridDecryptCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<HybridDecrypt>>>
  GetKeyManager(const std::string& type_url, const std::string& primitive_name,
                uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};

class TinkConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

typedef struct KeyTypeEntry {
  std::string catalogue_name;
  std::string primitive_name;
  std::string type_url;
  bool new_key_allowed;
  int key_manager_version;
} KeyTypeEntry;

TEST_F(TinkConfigTest, testBasic) {
  std::vector<KeyTypeEntry> all_key_type_entries;

  std::vector<KeyTypeEntry> mac_key_type_entries;
  mac_key_type_entries.push_back(
      {"TinkMac", "Mac",
       "type.googleapis.com/google.crypto.tink.HmacKey", true, 0});
  all_key_type_entries.insert(std::end(all_key_type_entries),
                              std::begin(mac_key_type_entries),
                              std::end(mac_key_type_entries));

  std::vector<KeyTypeEntry> aead_key_type_entries;
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey", true, 0});
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.AesGcmKey", true, 0});
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.AesGcmSivKey", true, 0});
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.AesEaxKey", true, 0});
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", true, 0});
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.KmsAeadKey", true, 0});
  aead_key_type_entries.push_back(
      {"TinkAead", "Aead",
       "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey", true, 0});
  all_key_type_entries.insert(std::end(all_key_type_entries),
                              std::begin(aead_key_type_entries),
                              std::end(aead_key_type_entries));

  std::vector<KeyTypeEntry> hybrid_key_type_entries;
  hybrid_key_type_entries.push_back(
      {"TinkHybridDecrypt", "HybridDecrypt",
       "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
       true, 0});
  hybrid_key_type_entries.push_back(
      {"TinkHybridEncrypt", "HybridEncrypt",
       "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
       true, 0});
  all_key_type_entries.insert(std::end(all_key_type_entries),
                              std::begin(hybrid_key_type_entries),
                              std::end(hybrid_key_type_entries));

  std::vector<KeyTypeEntry> signature_key_type_entries;
  signature_key_type_entries.push_back(
      {"TinkPublicKeySign", "PublicKeySign",
       "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey", true, 0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeyVerify", "PublicKeyVerify",
       "type.googleapis.com/google.crypto.tink.EcdsaPublicKey", true, 0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeySign", "PublicKeySign",
       "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey", true, 0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeyVerify", "PublicKeyVerify",
       "type.googleapis.com/google.crypto.tink.Ed25519PublicKey", true, 0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeySign", "PublicKeySign",
       "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey", true, 0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeyVerify", "PublicKeyVerify",
       "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey", true, 0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeySign", "PublicKeySign",
       "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey", true,
       0});
  signature_key_type_entries.push_back(
      {"TinkPublicKeyVerify", "PublicKeyVerify",
       "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey", true, 0});
  all_key_type_entries.insert(std::end(all_key_type_entries),
                              std::begin(signature_key_type_entries),
                              std::end(signature_key_type_entries));

  std::vector<KeyTypeEntry> daead_key_type_entries;
  daead_key_type_entries.push_back(
      {"TinkDeterministicAead", "DeterministicAead",
       "type.googleapis.com/google.crypto.tink.AesSivKey", true, 0});
  all_key_type_entries.insert(std::end(all_key_type_entries),
                              std::begin(daead_key_type_entries),
                              std::end(daead_key_type_entries));

  std::vector<KeyTypeEntry> saead_key_type_entries;
  saead_key_type_entries.push_back(
      {"TinkStreamingAead", "StreamingAead",
       "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
       true, 0});
  all_key_type_entries.insert(std::end(all_key_type_entries),
                              std::begin(saead_key_type_entries),
                              std::end(saead_key_type_entries));

  auto& config = TinkConfig::Latest();

  EXPECT_EQ(all_key_type_entries.size(), TinkConfig::Latest().entry_size());

  int i = 0;
  for (const auto& key_type_entry : all_key_type_entries) {
    EXPECT_EQ(key_type_entry.catalogue_name, config.entry(i).catalogue_name());
    EXPECT_EQ(key_type_entry.primitive_name, config.entry(i).primitive_name());
    EXPECT_EQ(key_type_entry.type_url, config.entry(i).type_url());
    EXPECT_EQ(key_type_entry.new_key_allowed,
              config.entry(i).new_key_allowed());
    EXPECT_EQ(key_type_entry.key_manager_version,
              config.entry(i).key_manager_version());
    i++;
  }

  // No key manager before registration.
  for (const auto& key_type_entry : aead_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<Aead>(key_type_entry.type_url);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  for (const auto& key_type_entry : mac_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<Mac>(key_type_entry.type_url);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  for (const auto& key_type_entry : hybrid_key_type_entries) {
    if (key_type_entry.catalogue_name == "TinkHybridEncrypt") {
      // HybridEncrypt
      auto manager_result =
          Registry::get_key_manager<HybridEncrypt>(key_type_entry.type_url);
      EXPECT_FALSE(manager_result.ok());
      EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
    } else {
      // HybridDecrypt
      auto manager_result =
          Registry::get_key_manager<HybridDecrypt>(key_type_entry.type_url);
      EXPECT_FALSE(manager_result.ok());
      EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
    }
  }
  for (const auto& key_type_entry : signature_key_type_entries) {
    if (key_type_entry.catalogue_name == "TinkPublicKeySign") {
      // PublicKeySign
      auto manager_result =
          Registry::get_key_manager<PublicKeySign>(key_type_entry.type_url);
      EXPECT_FALSE(manager_result.ok());
      EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
    } else {
      // PublicKeyVerify
      auto manager_result =
          Registry::get_key_manager<PublicKeyVerify>(key_type_entry.type_url);
      EXPECT_FALSE(manager_result.ok());
      EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
    }
  }
  for (const auto& key_type_entry : daead_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<DeterministicAead>(key_type_entry.type_url);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  for (const auto& key_type_entry : saead_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<StreamingAead>(key_type_entry.type_url);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }

  // Registration of standard key types works.
  auto status = TinkConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  for (const auto& key_type_entry : aead_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<Aead>(key_type_entry.type_url);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(
        manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
  }

  for (const auto& key_type_entry : mac_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<Mac>(key_type_entry.type_url);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(
        manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
  }

  for (const auto& key_type_entry : hybrid_key_type_entries) {
    if (key_type_entry.catalogue_name == "TinkHybridEncrypt") {
      auto manager_result =
          Registry::get_key_manager<HybridEncrypt>(key_type_entry.type_url);
      EXPECT_TRUE(manager_result.ok()) << manager_result.status();
      EXPECT_TRUE(
          manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
    } else {
      auto manager_result =
          Registry::get_key_manager<HybridDecrypt>(key_type_entry.type_url);
      EXPECT_TRUE(manager_result.ok()) << manager_result.status();
      EXPECT_TRUE(
          manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
    }
  }

  for (const auto& key_type_entry : signature_key_type_entries) {
    if (key_type_entry.catalogue_name == "TinkPublicKeySign") {
      auto manager_result =
          Registry::get_key_manager<PublicKeySign>(key_type_entry.type_url);
      EXPECT_TRUE(manager_result.ok()) << manager_result.status();
      EXPECT_TRUE(
          manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
    } else {
      auto manager_result =
          Registry::get_key_manager<PublicKeyVerify>(key_type_entry.type_url);
      EXPECT_TRUE(manager_result.ok()) << manager_result.status();
      EXPECT_TRUE(
          manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
    }
  }

  for (const auto& key_type_entry : daead_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<DeterministicAead>(key_type_entry.type_url);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(
        manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
  }

  for (const auto& key_type_entry : saead_key_type_entries) {
    auto manager_result =
        Registry::get_key_manager<StreamingAead>(key_type_entry.type_url);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(
        manager_result.ValueOrDie()->DoesSupport(key_type_entry.type_url));
  }
}  // namespace

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
  status = Registry::AddCatalogue(
      "TinkHybridDecrypt", absl::make_unique<DummyHybridDecryptCatalogue>());
  EXPECT_TRUE(status.ok()) << status;
  status = TinkConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
