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

#include "tink/mac/aes_cmac_key_manager.h"

#include "gtest/gtest.h"
#include "tink/mac.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_cmac.pb.h"
#include "proto/aes_ctr.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesCmacKey;
using google::crypto::tink::AesCmacKeyFormat;
using google::crypto::tink::AesCtrKey;
using google::crypto::tink::AesCtrKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;

namespace {

class AesCmacKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string cmac_key_type_ = "type.googleapis.com/google.crypto.tink.AesCmacKey";
};

TEST_F(AesCmacKeyManagerTest, testBasic) {
  AesCmacKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.AesCmacKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(AesCmacKeyManagerTest, testKeyDataErrors) {
  AesCmacKeyManager key_manager;

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
    key_data.set_type_url(cmac_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    AesCmacKey key;
    key.set_version(1);
    key_data.set_type_url(cmac_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(AesCmacKeyManagerTest, testKeyMessageErrors) {
  AesCmacKeyManager key_manager;

  {  // Bad protobuffer.
    AesCtrKey key_message;
    auto result = key_manager.GetPrimitive(key_message);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesCtrKey",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }
}

TEST_F(AesCmacKeyManagerTest, testPrimitives) {
  AesCmacKeyManager key_manager;
  AesCmacKey key;

  key.set_version(0);
  key.mutable_params()->set_tag_size(16);
  key.set_key_value("some key of sufficient length...");

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto cmac = std::move(result.ValueOrDie());
    auto cmac_result = cmac->ComputeMac("some data");
    EXPECT_TRUE(cmac_result.ok());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(cmac_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto cmac = std::move(result.ValueOrDie());
    auto cmac_result = cmac->ComputeMac("some data");
    EXPECT_TRUE(cmac_result.ok());
  }
}

TEST_F(AesCmacKeyManagerTest, testNewKeyErrors) {
  AesCmacKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Bad key format.
    AesCtrKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesCtrKeyFormat",
                        result.status().error_message());
  }

  {  // Bad serialized key format.
    auto result = key_factory.NewKey("some bad serialized proto");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad AesCmacKeyFormat: small key_size.
    AesCmacKeyFormat key_format;
    key_format.set_key_size(8);
    key_format.mutable_params()->set_tag_size(16);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "invalid key_size",
                        result.status().error_message());
  }

  {  // Bad AesCmacKeyFormat: BlockCipher not supported.
    AesCmacKeyFormat key_format;
    key_format.set_key_size(32);
    key_format.mutable_params()->set_tag_size(17);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "tag_size",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "too big",
                        result.status().error_message());
  }

  {  // Bad AesCmacKeyFormat: BlockCipher not supported.
    AesCmacKeyFormat key_format;
    key_format.set_key_size(32);
    key_format.mutable_params()->set_tag_size(9);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "tag_size",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "too small",
                        result.status().error_message());
  }
}

TEST_F(AesCmacKeyManagerTest, testNewKeyBasic) {
  AesCmacKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  AesCmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_tag_size(16);

  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(key_format);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix_ + key->GetTypeName(), cmac_key_type_);
    std::unique_ptr<AesCmacKey> cmac_key(
        static_cast<AesCmacKey*>(key.release()));
    EXPECT_EQ(0, cmac_key->version());
    EXPECT_EQ(16, cmac_key->params().tag_size());
    EXPECT_EQ(key_format.key_size(), cmac_key->key_value().size());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix_ + key->GetTypeName(), cmac_key_type_);
    std::unique_ptr<AesCmacKey> cmac_key(
        static_cast<AesCmacKey*>(key.release()));
    EXPECT_EQ(0, cmac_key->version());
    EXPECT_EQ(16, cmac_key->params().tag_size());
    EXPECT_EQ(key_format.key_size(), cmac_key->key_value().size());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(cmac_key_type_, key_data->type_url());
    EXPECT_EQ(KeyData::SYMMETRIC, key_data->key_material_type());
    AesCmacKey cmac_key;
    EXPECT_TRUE(cmac_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, cmac_key.version());
    EXPECT_EQ(16, cmac_key.params().tag_size());
    EXPECT_EQ(key_format.key_size(), cmac_key.key_value().size());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
