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

#include "cc/mac/hmac_key_manager.h"

#include "cc/mac.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "gtest/gtest.h"
#include "proto/aes_ctr.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

using google::cloud::crypto::tink::AesCtrKey;
using google::cloud::crypto::tink::HashType;
using google::cloud::crypto::tink::HmacKey;
using google::cloud::crypto::tink::HmacKeyFormat;
using google::cloud::crypto::tink::KeyData;
using google::cloud::crypto::tink::KeyTemplate;

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class HmacKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix = "type.googleapis.com/";
  std::string hmac_key_type =
      "type.googleapis.com/google.cloud.crypto.tink.HmacKey";
};

TEST_F(HmacKeyManagerTest, testBasic) {
  HmacKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.cloud.crypto.tink.HmacKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(HmacKeyManagerTest, testKeyDataErrors) {
  HmacKeyManager key_manager;

  {  // Bad key type.
    KeyData key_data;
    std::string bad_key_type =
        "type.googleapis.com/google.cloud.crypto.tink.SomeOtherKey";
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
    key_data.set_type_url(hmac_key_type);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    HmacKey key;
    key.set_version(1);
    key_data.set_type_url(key_type_prefix + key.GetDescriptor()->full_name());
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(HmacKeyManagerTest, testKeyMessageErrors) {
  HmacKeyManager key_manager;

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

// TODO(przydatek): do real verification of HMACs once they are implemented.
TEST_F(HmacKeyManagerTest, testPrimitives) {
  HmacKeyManager key_manager;
  HmacKey key;

  key.set_version(0);
  key.mutable_params()->set_tag_size(16);
  key.mutable_params()->set_hash(HashType::SHA256);
  key.set_key_value("some key of sufficient length");

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto hmac = std::move(result.ValueOrDie());
    auto hmac_result = hmac->ComputeMac("some data");
    EXPECT_TRUE(hmac_result.ok());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(key_type_prefix + key.GetDescriptor()->full_name());
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto hmac = std::move(result.ValueOrDie());
    auto hmac_result = hmac->ComputeMac("some data");
    EXPECT_TRUE(hmac_result.ok());
  }
}

TEST_F(HmacKeyManagerTest, testNewKeyErrors) {
  HmacKeyManager key_manager;

  {  // Bad key type.
    KeyTemplate key_template;
    KeyData key_data;
    std::string bad_key_type =
        "type.googleapis.com/google.cloud.crypto.tink.SomeOtherKey";
    key_template.set_type_url(bad_key_type);
    auto result = key_manager.NewKey(key_template);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, bad_key_type,
                        result.status().error_message());
  }

  {  // Bad key value.
    KeyTemplate key_template;
    key_template.set_type_url(hmac_key_type);
    key_template.set_value("some bad serialized proto");
    auto result = key_manager.NewKey(key_template);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad HmacKeyFormat: small key_size.
    HmacKeyFormat key_format;
    key_format.set_key_size(8);
    KeyTemplate key_template;
    key_template.set_type_url(hmac_key_type);
    key_template.set_value(key_format.SerializeAsString());
    auto result = key_manager.NewKey(key_template);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "key_size",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "too small",
                        result.status().error_message());
  }

  {  // Bad HmacKeyFormat: HashType not supported.
    HmacKeyFormat key_format;
    key_format.set_key_size(16);
    key_format.mutable_params()->set_tag_size(10);
    KeyTemplate key_template;
    key_template.set_type_url(hmac_key_type);
    key_template.set_value(key_format.SerializeAsString());
    auto result = key_manager.NewKey(key_template);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "HashType",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }

  {  // Bad HmacKeyFormat: tag_size too small.
    HmacKeyFormat key_format;
    key_format.set_key_size(16);
    key_format.mutable_params()->set_hash(HashType::SHA256);
    key_format.mutable_params()->set_tag_size(8);
    KeyTemplate key_template;
    key_template.set_type_url(hmac_key_type);
    key_template.set_value(key_format.SerializeAsString());
    auto result = key_manager.NewKey(key_template);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "tag_size",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "too small",
                        result.status().error_message());
  }

  {  // Bad HmacKeyFormat: tag_size too big.
    HmacKeyFormat key_format;
    key_format.set_key_size(16);
    key_format.mutable_params()->set_hash(HashType::SHA256);
    key_format.mutable_params()->set_tag_size(42);
    KeyTemplate key_template;
    key_template.set_type_url(hmac_key_type);
    key_template.set_value(key_format.SerializeAsString());
    auto result = key_manager.NewKey(key_template);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "tag_size",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "too big",
                        result.status().error_message());
  }
}

TEST_F(HmacKeyManagerTest, testNewKeyBasic) {
  HmacKeyManager key_manager;
  HmacKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_hash(HashType::SHA256);
  key_format.mutable_params()->set_tag_size(18);
  KeyTemplate key_template;
  key_template.set_type_url(hmac_key_type);
  key_template.set_value(key_format.SerializeAsString());
  auto result = key_manager.NewKey(key_template);
  EXPECT_TRUE(result.ok()) << result.status();
  auto key = std::move(result.ValueOrDie());
  EXPECT_EQ(key_type_prefix + key->GetDescriptor()->full_name(), hmac_key_type);
  std::unique_ptr<HmacKey> hmac_key(reinterpret_cast<HmacKey*>(key.release()));
  EXPECT_EQ(0, hmac_key->version());
  EXPECT_EQ(key_format.params().hash(), hmac_key->params().hash());
  EXPECT_EQ(key_format.params().tag_size(), hmac_key->params().tag_size());
  EXPECT_EQ(key_format.key_size(), hmac_key->key_value().size());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
