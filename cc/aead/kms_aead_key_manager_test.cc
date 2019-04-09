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

#include "tink/aead/kms_aead_key_manager.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "tink/util/test_matchers.h"
#include "gtest/gtest.h"
#include "proto/aes_eax.pb.h"
#include "proto/kms_aead.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using crypto::tink::test::DummyKmsClient;
using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::KmsAeadKey;
using google::crypto::tink::KmsAeadKeyFormat;
using google::crypto::tink::KeyData;
using testing::HasSubstr;

namespace {

class KmsAeadKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string kms_aead_key_type_ =
      "type.googleapis.com/google.crypto.tink.KmsAeadKey";
};

TEST_F(KmsAeadKeyManagerTest, testBasic) {
  KmsAeadKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.KmsAeadKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(KmsAeadKeyManagerTest, testKeyDataErrors) {
  KmsAeadKeyManager key_manager;

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
    key_data.set_type_url(kms_aead_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    KmsAeadKey key;
    key.set_version(1);
    key_data.set_type_url(kms_aead_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(KmsAeadKeyManagerTest, testKeyMessageErrors) {
  KmsAeadKeyManager key_manager;

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


TEST_F(KmsAeadKeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";

  // Initialize KmsClients.
  std::string uri_1_prefix = "prefix1";
  std::string uri_2_prefix = "prefix2";
  std::string uri_1 = absl::StrCat(uri_1_prefix + ":some_uri1");
  std::string uri_2 = absl::StrCat(uri_2_prefix + ":some_uri2");
  auto status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(uri_1_prefix, uri_1));
  EXPECT_THAT(status, IsOk());
  status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(uri_2_prefix, ""));
  EXPECT_THAT(status, IsOk());

  KmsAeadKeyManager key_manager;
  KmsAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_key_uri(uri_1);

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto kms_aead = std::move(result.ValueOrDie());
    auto encrypt_result = kms_aead->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto ciphertext = encrypt_result.ValueOrDie();
    EXPECT_THAT(ciphertext, HasSubstr(uri_1));
    auto decrypt_result = kms_aead->Decrypt(ciphertext, aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(kms_aead_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto kms_aead = std::move(result.ValueOrDie());
    auto encrypt_result = kms_aead->Encrypt(plaintext, aad);
    auto ciphertext = encrypt_result.ValueOrDie();
    EXPECT_THAT(ciphertext, HasSubstr(uri_1));
    auto decrypt_result = kms_aead->Decrypt(ciphertext, aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using key message and a KmsClient not bound to a specific key.
    key.mutable_params()->set_key_uri(uri_2);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto kms_aead = std::move(result.ValueOrDie());
    auto encrypt_result = kms_aead->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto ciphertext = encrypt_result.ValueOrDie();
    EXPECT_THAT(ciphertext, HasSubstr(uri_2));
    auto decrypt_result = kms_aead->Decrypt(ciphertext, aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Try using a key message with an unknown URI.
    key.mutable_params()->set_key_uri("some unknown uri");
    auto result = key_manager.GetPrimitive(key);
    EXPECT_THAT(result.status(), StatusIs(util::error::NOT_FOUND,
                                          HasSubstr("KmsClient")));
  }
}

TEST_F(KmsAeadKeyManagerTest, testNewKeyErrors) {
  KmsAeadKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Bad key format.
    AesEaxKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesEaxKeyFormat",
                        result.status().error_message());
  }

  {  // Bad serialized key format.
    auto result = key_factory.NewKey("some bad serialized proto");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }
}

TEST_F(KmsAeadKeyManagerTest, testNewKeyBasic) {
  KmsAeadKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  KmsAeadKeyFormat key_format;
  key_format.set_key_uri("some key uri");

  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(key_format);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix_ + key->GetTypeName(), kms_aead_key_type_);
    std::unique_ptr<KmsAeadKey> kms_aead_key(
        reinterpret_cast<KmsAeadKey*>(key.release()));
    EXPECT_EQ(0, kms_aead_key->version());
    EXPECT_EQ(key_format.key_uri(), kms_aead_key->params().key_uri());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix_ + key->GetTypeName(), kms_aead_key_type_);
    std::unique_ptr<KmsAeadKey> kms_aead_key(
        reinterpret_cast<KmsAeadKey*>(key.release()));
    EXPECT_EQ(0, kms_aead_key->version());
    EXPECT_EQ(key_format.key_uri(), kms_aead_key->params().key_uri());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(kms_aead_key_type_, key_data->type_url());
    EXPECT_EQ(KeyData::REMOTE, key_data->key_material_type());
    KmsAeadKey kms_aead_key;
    EXPECT_TRUE(kms_aead_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, kms_aead_key.version());
    EXPECT_EQ(key_format.key_uri(), kms_aead_key.params().key_uri());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
