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

#include "tink/aead/aes_eax_key_manager.h"

#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;

namespace {

class AesEaxKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix = "type.googleapis.com/";
  std::string aes_eax_key_type =
      "type.googleapis.com/google.crypto.tink.AesEaxKey";
};

TEST_F(AesEaxKeyManagerTest, testBasic) {
  AesEaxKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.AesEaxKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(AesEaxKeyManagerTest, testKeyDataErrors) {
  AesEaxKeyManager key_manager;

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
    key_data.set_type_url(aes_eax_key_type);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    AesEaxKey key;
    key.set_version(1);
    key_data.set_type_url(aes_eax_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }

  {  // Bad key_value size (supported sizes: 16, 32).
    for (int len = 0; len < 42; len++) {
      AesEaxKey key;
      key.set_version(0);
      key.set_key_value(std::string(len, 'a'));
      key.mutable_params()->set_iv_size(12);
      KeyData key_data;
      key_data.set_type_url(aes_eax_key_type);
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

  {  // Bad iv_size value (supported sizes: 12, 16).
    int key_size = 16;
    for (int iv_size = 0; iv_size < 42; iv_size++) {
      AesEaxKey key;
      key.set_version(0);
      key.set_key_value(std::string(key_size, 'a'));
      key.mutable_params()->set_iv_size(iv_size);
      KeyData key_data;
      key_data.set_type_url(aes_eax_key_type);
      key_data.set_value(key.SerializeAsString());
      auto result = key_manager.GetPrimitive(key_data);
      if (iv_size == 12 || iv_size == 16) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT,
                  result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring,
                            std::to_string(iv_size) + " bytes",
                            result.status().error_message());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                            result.status().error_message());
      }
    }
  }
}

TEST_F(AesEaxKeyManagerTest, testKeyMessageErrors) {
  AesEaxKeyManager key_manager;

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

  {  // Bad key_value size (supported sizes: 16, 32).
    for (int len = 0; len < 42; len++) {
      AesEaxKey key;
      key.set_version(0);
      key.set_key_value(std::string(len, 'a'));
      key.mutable_params()->set_iv_size(16);
      auto result = key_manager.GetPrimitive(key);
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

  {  // Bad iv_size value (supported sizes: 12, 16).
    int key_size = 32;
    for (int iv_size = 0; iv_size < 42; iv_size++) {
      AesEaxKey key;
      key.set_version(0);
      key.set_key_value(std::string(key_size, 'a'));
      key.mutable_params()->set_iv_size(iv_size);
      auto result = key_manager.GetPrimitive(key);
      if (iv_size == 12 || iv_size == 16) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT,
                  result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring,
                            std::to_string(iv_size) + " bytes",
                            result.status().error_message());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                            result.status().error_message());
      }
    }
  }
}

TEST_F(AesEaxKeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";
  AesEaxKeyManager key_manager;
  AesEaxKey key;

  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_iv_size(16);

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto aes_eax = std::move(result.ValueOrDie());
    auto encrypt_result = aes_eax->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto decrypt_result = aes_eax->Decrypt(encrypt_result.ValueOrDie(), aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(aes_eax_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto aes_eax = std::move(result.ValueOrDie());
    auto encrypt_result = aes_eax->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto decrypt_result = aes_eax->Decrypt(encrypt_result.ValueOrDie(), aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }
}

TEST_F(AesEaxKeyManagerTest, testNewKeyErrors) {
  AesEaxKeyManager key_manager;
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

  {  // Bad AesEaxKeyFormat: small key_size.
    AesEaxKeyFormat key_format;
    key_format.set_key_size(8);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "key_size",
                        result.status().error_message());
  }
}

TEST_F(AesEaxKeyManagerTest, testNewKeyBasic) {
  AesEaxKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  AesEaxKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_iv_size(12);

  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(key_format);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix + key->GetTypeName(), aes_eax_key_type);
    std::unique_ptr<AesEaxKey> aes_eax_key(
        reinterpret_cast<AesEaxKey*>(key.release()));
    EXPECT_EQ(0, aes_eax_key->version());
    EXPECT_EQ(key_format.key_size(), aes_eax_key->key_value().size());
    EXPECT_EQ(key_format.params().iv_size(), aes_eax_key->params().iv_size());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix + key->GetTypeName(), aes_eax_key_type);
    std::unique_ptr<AesEaxKey> aes_eax_key(
        reinterpret_cast<AesEaxKey*>(key.release()));
    EXPECT_EQ(0, aes_eax_key->version());
    EXPECT_EQ(key_format.key_size(), aes_eax_key->key_value().size());
    EXPECT_EQ(key_format.params().iv_size(), aes_eax_key->params().iv_size());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(aes_eax_key_type, key_data->type_url());
    EXPECT_EQ(KeyData::SYMMETRIC, key_data->key_material_type());
    AesEaxKey aes_eax_key;
    EXPECT_TRUE(aes_eax_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, aes_eax_key.version());
    EXPECT_EQ(key_format.key_size(), aes_eax_key.key_value().size());
    EXPECT_EQ(key_format.params().iv_size(), aes_eax_key.params().iv_size());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
