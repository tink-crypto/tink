// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_sign_key_manager.h"

#include "gtest/gtest.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/registry.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/empty.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::Ed25519PrivateKey;
using google::crypto::tink::Empty;
using google::crypto::tink::KeyData;

namespace {

class Ed25519SignKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string ed25519_sign_key_type_ =
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
};

TEST_F(Ed25519SignKeyManagerTest, testBasic) {
  Ed25519SignKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(Ed25519SignKeyManagerTest, testKeyDataErrors) {
  Ed25519SignKeyManager key_manager;

  {  // Bad key type.
    KeyData key_data;
    std::string bad_key_type = "type.googleapis.com/google.crypto.tink.SomeOtherKey";
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
    key_data.set_type_url(ed25519_sign_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    Ed25519PrivateKey key;
    key.set_version(1);
    key_data.set_type_url(ed25519_sign_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(Ed25519SignKeyManagerTest, testKeyMessageErrors) {
  Ed25519SignKeyManager key_manager;

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

TEST_F(Ed25519SignKeyManagerTest, testPrimitives) {
  std::string message = "some message to sign";
  Ed25519SignKeyManager sign_key_manager;
  Ed25519PrivateKey key = test::GetEd25519TestPrivateKey();

  {  // Using Key proto.
    auto result = sign_key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto sign = std::move(result.ValueOrDie());
    auto signing_result = sign->Sign(message);
    EXPECT_TRUE(signing_result.ok()) << signing_result.status();
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(ed25519_sign_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = sign_key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto sign = std::move(result.ValueOrDie());
    auto signing_result = sign->Sign(message);
    EXPECT_TRUE(signing_result.ok()) << signing_result.status();
  }
}

TEST_F(Ed25519SignKeyManagerTest, testPublicKeyExtraction) {
  Ed25519SignKeyManager key_manager;
  auto private_key_factory =
      dynamic_cast<const PrivateKeyFactory*>(&(key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);

  auto new_key_result =
      private_key_factory->NewKey(SignatureKeyTemplates::Ed25519().value());
  std::unique_ptr<Ed25519PrivateKey> new_key(
      reinterpret_cast<Ed25519PrivateKey*>(
          new_key_result.ValueOrDie().release()));
  auto public_key_data_result =
      private_key_factory->GetPublicKeyData(new_key->SerializeAsString());
  EXPECT_TRUE(public_key_data_result.ok()) << public_key_data_result.status();
  auto public_key_data = std::move(public_key_data_result.ValueOrDie());
  EXPECT_EQ(Ed25519VerifyKeyManager::static_key_type(),
            public_key_data->type_url());
  EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC, public_key_data->key_material_type());
  EXPECT_EQ(new_key->public_key().SerializeAsString(),
            public_key_data->value());
}

TEST_F(Ed25519SignKeyManagerTest, testPublicKeyExtractionErrors) {
  Ed25519SignKeyManager key_manager;
  auto private_key_factory =
      dynamic_cast<const PrivateKeyFactory*>(&(key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);

  AesGcmKeyManager aead_key_manager;
  auto aead_private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(aead_key_manager.get_key_factory()));
  ASSERT_EQ(nullptr, aead_private_key_factory);

  auto aead_key_result = aead_key_manager.get_key_factory().NewKey(
      AeadKeyTemplates::Aes128Gcm().value());
  ASSERT_TRUE(aead_key_result.ok()) << aead_key_result.status();
  auto aead_key = std::move(aead_key_result.ValueOrDie());
  auto public_key_data_result =
      private_key_factory->GetPublicKeyData(aead_key->SerializeAsString());
  EXPECT_FALSE(public_key_data_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            public_key_data_result.status().error_code());
}

TEST_F(Ed25519SignKeyManagerTest, testNewKey) {
  Ed25519SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  Empty key_format;
  auto result = key_factory.NewKey(key_format);
  EXPECT_TRUE(result.ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
