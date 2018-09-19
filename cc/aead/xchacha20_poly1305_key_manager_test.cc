// Copyright 2018 Google Inc.
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

#include "tink/aead/xchacha20_poly1305_key_manager.h"

#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::XChaCha20Poly1305Key;

namespace {

class XChaCha20Poly1305KeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix = "type.googleapis.com/";
  std::string xchaha20_poly1305_key_type =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
};

TEST_F(XChaCha20Poly1305KeyManagerTest, testBasic) {
  XChaCha20Poly1305KeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(XChaCha20Poly1305KeyManagerTest, testKeyDataErrors) {
  XChaCha20Poly1305KeyManager key_manager;

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
    key_data.set_type_url(xchaha20_poly1305_key_type);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    XChaCha20Poly1305Key key;
    key.set_version(1);
    key_data.set_type_url(xchaha20_poly1305_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }

  {  // Bad key_value size (supported size: 32).
    for (int len = 0; len < 42; len++) {
      XChaCha20Poly1305Key key;
      key.set_version(0);
      key.set_key_value(std::string(len, 'a'));
      KeyData key_data;
      key_data.set_type_url(xchaha20_poly1305_key_type);
      key_data.set_value(key.SerializeAsString());
      auto result = key_manager.GetPrimitive(key_data);
      if (len == 32) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring,
                            std::to_string(len) + " bytes",
                            result.status().error_message());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported size",
                            result.status().error_message());
      }
    }
  }
}

TEST_F(XChaCha20Poly1305KeyManagerTest, testKeyMessageErrors) {
  XChaCha20Poly1305KeyManager key_manager;

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

  {  // Bad key_value size (supported size: 32).
    for (int len = 0; len < 42; len++) {
      XChaCha20Poly1305Key key;
      key.set_version(0);
      key.set_key_value(std::string(len, 'a'));
      auto result = key_manager.GetPrimitive(key);
      if (len == 32) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring,
                            std::to_string(len) + " bytes",
                            result.status().error_message());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported size",
                            result.status().error_message());
      }
    }
  }
}

TEST_F(XChaCha20Poly1305KeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";
  XChaCha20Poly1305KeyManager key_manager;
  XChaCha20Poly1305Key key;

  key.set_version(0);
  key.set_key_value("32 bytes of key 0123456789abcdef");

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto xchaha20_poly1305 = std::move(result.ValueOrDie());
    auto encrypt_result = xchaha20_poly1305->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto decrypt_result =
        xchaha20_poly1305->Decrypt(encrypt_result.ValueOrDie(), aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(xchaha20_poly1305_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto xchaha20_poly1305 = std::move(result.ValueOrDie());
    auto encrypt_result = xchaha20_poly1305->Encrypt(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    auto decrypt_result =
        xchaha20_poly1305->Decrypt(encrypt_result.ValueOrDie(), aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }
}

TEST_F(XChaCha20Poly1305KeyManagerTest, testNewKeyBasic) {
  XChaCha20Poly1305KeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(nullptr /* ignored */);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix + key->GetTypeName(), xchaha20_poly1305_key_type);
    std::unique_ptr<XChaCha20Poly1305Key> xchaha20_poly1305_key(
        static_cast<XChaCha20Poly1305Key*>(key.release()));
    EXPECT_EQ(0, xchaha20_poly1305_key->version());
    EXPECT_EQ(32, xchaha20_poly1305_key->key_value().size());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey("" /* ignored */);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix + key->GetTypeName(), xchaha20_poly1305_key_type);
    std::unique_ptr<XChaCha20Poly1305Key> xchaha20_poly1305_key(
        static_cast<XChaCha20Poly1305Key*>(key.release()));
    EXPECT_EQ(0, xchaha20_poly1305_key->version());
    EXPECT_EQ(32, xchaha20_poly1305_key->key_value().size());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData("" /* ignored */);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(xchaha20_poly1305_key_type, key_data->type_url());
    EXPECT_EQ(KeyData::SYMMETRIC, key_data->key_material_type());
    XChaCha20Poly1305Key xchaha20_poly1305_key;
    EXPECT_TRUE(xchaha20_poly1305_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, xchaha20_poly1305_key.version());
    EXPECT_EQ(32, xchaha20_poly1305_key.key_value().size());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
