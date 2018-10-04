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

#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"

#include "tink/hybrid_decrypt.h"
#include "tink/registry.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;

namespace {

class EciesAeadHkdfPrivateKeyManagerTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    ASSERT_TRUE(Registry::RegisterKeyManager(
                    absl::make_unique<AesGcmKeyManager>(), true)
                    .ok());
    ASSERT_TRUE(Registry::RegisterKeyManager(
                    absl::make_unique<AesCtrHmacAeadKeyManager>(), true)
                    .ok());
  }

  std::string key_type_prefix = "type.googleapis.com/";
  std::string ecies_private_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
};

// Checks whether given key is compatible with the given format.
void CheckNewKey(const EciesAeadHkdfPrivateKey& ecies_key,
                 const EciesAeadHkdfKeyFormat& key_format) {
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(0, ecies_key.version());
  EXPECT_TRUE(ecies_key.has_public_key());
  EXPECT_GT(ecies_key.key_value().length(), 0);
  EXPECT_EQ(0, ecies_key.public_key().version());
  EXPECT_GT(ecies_key.public_key().x().length(), 0);
  EXPECT_GT(ecies_key.public_key().y().length(), 0);
  EXPECT_EQ(ecies_key.public_key().params().SerializeAsString(),
            key_format.params().SerializeAsString());
  auto primitive_result = key_manager.GetPrimitive(ecies_key);
  EXPECT_TRUE(primitive_result.ok()) << primitive_result.status();
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testBasic) {
  EciesAeadHkdfPrivateKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testKeyDataErrors) {
  EciesAeadHkdfPrivateKeyManager key_manager;

  {  // Bad key type.
    KeyData key_data;
    std::string bad_key_type =
        "type.googleapis.com/google.crypto.tink.SomeOtherKey";
    key_data.set_type_url(bad_key_type);
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, bad_key_type,
                        result.status().error_message());
  }

  {  // Bad key value.
    KeyData key_data;
    key_data.set_type_url(ecies_private_key_type);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    EciesAeadHkdfPrivateKey key;
    key.set_version(1);
    key_data.set_type_url(ecies_private_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testKeyMessageErrors) {
  EciesAeadHkdfPrivateKeyManager key_manager;

  {  // Bad protobuffer.
    AesEaxKey key;
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesEaxKey",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string context_info = "some context info";
  EciesAeadHkdfPublicKeyManager public_key_manager;
  EciesAeadHkdfPrivateKeyManager private_key_manager;
  EciesAeadHkdfPrivateKey key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED,
      HashType::SHA256, 32);
  auto hybrid_encrypt = std::move(public_key_manager.GetPrimitive(
      key.public_key()).ValueOrDie());
  std::string ciphertext =
      hybrid_encrypt->Encrypt(plaintext, context_info).ValueOrDie();

  {  // Using Key proto.
    auto result = private_key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto hybrid_decrypt = std::move(result.ValueOrDie());
    auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(ecies_private_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = private_key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto hybrid_decrypt = std::move(result.ValueOrDie());
    auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  }
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testNewKeyCreation) {
  EciesAeadHkdfPrivateKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  { // Via NewKey(format_proto).
    EciesAeadHkdfKeyFormat key_format;
    ASSERT_TRUE(key_format.ParseFromString(
        HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm().value()));
    auto result = key_factory.NewKey(key_format);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    ASSERT_EQ(ecies_private_key_type, key_type_prefix + key->GetTypeName());
    std::unique_ptr<EciesAeadHkdfPrivateKey> ecies_key(
        reinterpret_cast<EciesAeadHkdfPrivateKey*>(key.release()));
    CheckNewKey(*ecies_key, key_format);
  }

  { // Via NewKey(serialized_format_proto).
    EciesAeadHkdfKeyFormat key_format;
    ASSERT_TRUE(key_format.ParseFromString(
        HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256()
        .value()));
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    ASSERT_EQ(ecies_private_key_type, key_type_prefix + key->GetTypeName());
    std::unique_ptr<EciesAeadHkdfPrivateKey> ecies_key(
        reinterpret_cast<EciesAeadHkdfPrivateKey*>(key.release()));
    CheckNewKey(*ecies_key, key_format);
  }

  { // Via NewKeyData(serialized_format_proto).
    EciesAeadHkdfKeyFormat key_format;
    ASSERT_TRUE(key_format.ParseFromString(
        HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256()
        .value()));
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(ecies_private_key_type, key_data->type_url());
    EXPECT_EQ(KeyData::ASYMMETRIC_PRIVATE, key_data->key_material_type());
    EciesAeadHkdfPrivateKey ecies_key;
    ASSERT_TRUE(ecies_key.ParseFromString(key_data->value()));
    CheckNewKey(ecies_key, key_format);
  }
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testPublicKeyExtraction) {
  EciesAeadHkdfPrivateKeyManager key_manager;
  auto private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);

  auto new_key_result = private_key_factory->NewKey(
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256().value());
  std::unique_ptr<EciesAeadHkdfPrivateKey> new_key(
      reinterpret_cast<EciesAeadHkdfPrivateKey*>(
          new_key_result.ValueOrDie().release()));
  auto public_key_data_result = private_key_factory->GetPublicKeyData(
      new_key->SerializeAsString());
  EXPECT_TRUE(public_key_data_result.ok()) << public_key_data_result.status();
  auto public_key_data = std::move(public_key_data_result.ValueOrDie());
  EXPECT_EQ(EciesAeadHkdfPublicKeyManager::static_key_type(),
            public_key_data->type_url());
  EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC, public_key_data->key_material_type());
  EXPECT_EQ(new_key->public_key().SerializeAsString(),
            public_key_data->value());
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testPublicKeyExtractionErrors) {
  EciesAeadHkdfPrivateKeyManager key_manager;
  auto private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);

  AesCtrHmacAeadKeyManager aead_key_manager;
  auto aead_private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(aead_key_manager.get_key_factory()));
  ASSERT_EQ(nullptr, aead_private_key_factory);

  auto aead_key_result = aead_key_manager.get_key_factory().NewKey(
      AeadKeyTemplates::Aes128CtrHmacSha256().value());
  ASSERT_TRUE(aead_key_result.ok()) << aead_key_result.status();
  auto aead_key = std::move(aead_key_result.ValueOrDie());
  auto public_key_data_result = private_key_factory->GetPublicKeyData(
      aead_key->SerializeAsString());
  EXPECT_FALSE(public_key_data_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            public_key_data_result.status().error_code());
}

TEST_F(EciesAeadHkdfPrivateKeyManagerTest, testNewKeyErrors) {
  EciesAeadHkdfPrivateKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  // Empty key format.
  EciesAeadHkdfKeyFormat key_format;
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Missing params",
                        result.status().error_message());
  }

  // Missing kem_params.
  auto params = key_format.mutable_params();
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Missing kem_params",
                        result.status().error_message());
  }

  // Invalid kem_params.
  auto kem_params = params->mutable_kem_params();
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Invalid kem_params",
                        result.status().error_message());
  }

  // Missing dem_params.
  kem_params->set_curve_type(EllipticCurveType::NIST_P256);
  kem_params->set_hkdf_hash_type(HashType::SHA256);
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Missing dem_params",
                        result.status().error_message());
  }

  // Invalid dem_params.
  auto dem_params = params->mutable_dem_params();
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Invalid dem_params",
                        result.status().error_message());
  }

  // Invalid EC point format.
  dem_params->mutable_aead_dem()->set_type_url("some type_url");
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unknown EC point format",
                        result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
