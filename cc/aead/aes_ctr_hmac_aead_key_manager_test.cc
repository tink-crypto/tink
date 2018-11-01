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

#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"

#include "tink/config.h"
#include "tink/mac/mac_config.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesCtrHmacAeadKey;
using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;

namespace {

class AesCtrHmacAeadKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix = "type.googleapis.com/";
  std::string aes_ctr_hmac_aead_key_type =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  void SetUp() override {
    // Initialize Tink.
    auto status = MacConfig::Register();
    if (!status.ok()) {
      std::clog << "Tink initialization failed: " << status << std::endl;
      exit(1);
    }
  }
};

TEST_F(AesCtrHmacAeadKeyManagerTest, testBasic) {
  AesCtrHmacAeadKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(AesCtrHmacAeadKeyManagerTest, testKeyDataErrors) {
  AesCtrHmacAeadKeyManager key_manager;

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
    key_data.set_type_url(aes_ctr_hmac_aead_key_type);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    AesCtrHmacAeadKey key;
    key.set_version(1);
    key_data.set_type_url(aes_ctr_hmac_aead_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }

  {  // Bad key_value size (supported sizes: 16 or 32).
    for (int len = 0; len < 42; len++) {
      AesCtrHmacAeadKey key;
      key.set_version(0);
      auto aes_ctr_key = key.mutable_aes_ctr_key();
      aes_ctr_key->set_key_value(std::string(len, 'a'));
      aes_ctr_key->mutable_params()->set_iv_size(12);
      auto hmac_key = key.mutable_hmac_key();
      hmac_key->set_key_value(std::string(len, 'b'));
      hmac_key->mutable_params()->set_hash(HashType::SHA1);
      hmac_key->mutable_params()->set_tag_size(10);
      KeyData key_data;
      key_data.set_type_url(aes_ctr_hmac_aead_key_type);
      key_data.set_value(key.SerializeAsString());
      auto result = key_manager.GetPrimitive(key_data);
      if (len == 16 || len == 32) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
          EXPECT_FALSE(result.ok());
          EXPECT_EQ(util::error::INVALID_ARGUMENT,
                    result.status().error_code());
          EXPECT_PRED_FORMAT2(testing::IsSubstring,
                              std::to_string(len) + " bytes",
                              result.status().error_message());
          EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                              result.status().error_message());
        }
    }
  }
}

TEST_F(AesCtrHmacAeadKeyManagerTest, testKeyMessageErrors) {
  AesCtrHmacAeadKeyManager key_manager;

  {  // Bad protobuffer.
    AesGcmKey key;
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesGcmKey",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }

  {  // Bad key_value size (supported sizes: 16 or 32).
    for (int len = 0; len < 42; len++) {
      AesCtrHmacAeadKey key;
      key.set_version(0);
      auto aes_ctr_key = key.mutable_aes_ctr_key();
      aes_ctr_key->set_key_value(std::string(len, 'a'));
      aes_ctr_key->mutable_params()->set_iv_size(12);
      auto hmac_key = key.mutable_hmac_key();
      hmac_key->set_key_value(std::string(len, 'b'));
      hmac_key->mutable_params()->set_hash(HashType::SHA1);
      hmac_key->mutable_params()->set_tag_size(10);
      auto result = key_manager.GetPrimitive(key);
      if (len == 16 || len == 32) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring,
                            std::to_string(len) + " bytes",
                            result.status().error_message());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                            result.status().error_message());
      }
    }
  }
}

TEST_F(AesCtrHmacAeadKeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";
  AesCtrHmacAeadKeyManager key_manager;
  AesCtrHmacAeadKey key;

  key.set_version(0);
  auto aes_ctr_key = key.mutable_aes_ctr_key();
  aes_ctr_key->set_key_value(std::string(16, 'a'));
  aes_ctr_key->mutable_params()->set_iv_size(12);
  auto hmac_key = key.mutable_hmac_key();
  hmac_key->set_key_value(std::string(16, 'b'));
  hmac_key->mutable_params()->set_hash(HashType::SHA1);
  hmac_key->mutable_params()->set_tag_size(10);

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto cipher = std::move(result.ValueOrDie());
    auto encrypt_result = cipher->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto decrypt_result = cipher->Decrypt(encrypt_result.ValueOrDie(), aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(aes_ctr_hmac_aead_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto cipher = std::move(result.ValueOrDie());
    auto encrypt_result = cipher->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto decrypt_result = cipher->Decrypt(encrypt_result.ValueOrDie(), aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }
}

TEST_F(AesCtrHmacAeadKeyManagerTest, testNewKeyErrors) {
  AesCtrHmacAeadKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Bad key format.
    AesGcmKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesGcmKeyFormat",
                        result.status().error_message());
  }

  {  // Bad serialized key format.
    auto result = key_factory.NewKey("some bad serialized proto");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad AesCtrHmacAeadKeyFormat: small key_size.
    AesCtrHmacAeadKeyFormat key_format;
    key_format.mutable_aes_ctr_key_format()->set_key_size(8);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "8 bytes",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                        result.status().error_message());
  }

  {  // Bad AesCtrHmacAeadKeyFormat: small HMAC key_size.
    AesCtrHmacAeadKeyFormat key_format;
    auto aes_ctr_key_format = key_format.mutable_aes_ctr_key_format();
    aes_ctr_key_format->set_key_size(16);
    aes_ctr_key_format->mutable_params()->set_iv_size(12);
    key_format.mutable_hmac_key_format()->set_key_size(8);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "key_size",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "too small",
                        result.status().error_message());
  }
}

TEST_F(AesCtrHmacAeadKeyManagerTest, testNewKeyBasic) {
  AesCtrHmacAeadKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  AesCtrHmacAeadKeyFormat key_format;
  auto aes_ctr_key_format = key_format.mutable_aes_ctr_key_format();
  aes_ctr_key_format->set_key_size(16);
  aes_ctr_key_format->mutable_params()->set_iv_size(12);
  auto hmac_key_format = key_format.mutable_hmac_key_format();
  hmac_key_format->set_key_size(16);
  hmac_key_format->mutable_params()->set_hash(HashType::SHA1);
  hmac_key_format->mutable_params()->set_tag_size(10);

  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(key_format);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix + key->GetTypeName(), aes_ctr_hmac_aead_key_type);
    std::unique_ptr<AesCtrHmacAeadKey> aes_ctr_hmac_aead_key(
        static_cast<AesCtrHmacAeadKey*>(key.release()));
    EXPECT_EQ(0, aes_ctr_hmac_aead_key->version());
    EXPECT_EQ(key_format.aes_ctr_key_format().key_size(),
              aes_ctr_hmac_aead_key->aes_ctr_key().key_value().size());
    auto& hmac_key_format = key_format.hmac_key_format();
    auto& hmac_key = aes_ctr_hmac_aead_key->hmac_key();
    EXPECT_EQ(hmac_key_format.params().hash(), hmac_key.params().hash());
    EXPECT_EQ(hmac_key_format.params().tag_size(),
              hmac_key.params().tag_size());
    EXPECT_EQ(hmac_key_format.key_size(), hmac_key.key_value().size());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix + key->GetTypeName(), aes_ctr_hmac_aead_key_type);
    std::unique_ptr<AesCtrHmacAeadKey> aes_ctr_hmac_aead_key(
        static_cast<AesCtrHmacAeadKey*>(key.release()));
    EXPECT_EQ(0, aes_ctr_hmac_aead_key->version());
    EXPECT_EQ(key_format.aes_ctr_key_format().key_size(),
              aes_ctr_hmac_aead_key->aes_ctr_key().key_value().size());
    auto& hmac_key_format = key_format.hmac_key_format();
    auto& hmac_key = aes_ctr_hmac_aead_key->hmac_key();
    EXPECT_EQ(hmac_key_format.params().hash(), hmac_key.params().hash());
    EXPECT_EQ(hmac_key_format.params().tag_size(),
              hmac_key.params().tag_size());
    EXPECT_EQ(hmac_key_format.key_size(), hmac_key.key_value().size());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(aes_ctr_hmac_aead_key_type, key_data->type_url());
    EXPECT_EQ(KeyData::SYMMETRIC, key_data->key_material_type());
    AesCtrHmacAeadKey aes_ctr_hmac_aead_key;
    EXPECT_TRUE(aes_ctr_hmac_aead_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, aes_ctr_hmac_aead_key.version());
    EXPECT_EQ(key_format.aes_ctr_key_format().key_size(),
              aes_ctr_hmac_aead_key.aes_ctr_key().key_value().size());
    auto& hmac_key_format = key_format.hmac_key_format();
    auto& hmac_key = aes_ctr_hmac_aead_key.hmac_key();
    EXPECT_EQ(hmac_key_format.params().hash(), hmac_key.params().hash());
    EXPECT_EQ(hmac_key_format.params().tag_size(),
              hmac_key.params().tag_size());
    EXPECT_EQ(hmac_key_format.key_size(), hmac_key.key_value().size());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
