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

#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"

#include "tink/hybrid_encrypt.h"
#include "tink/registry.h"
#include "tink/aead/aes_gcm_key_manager.h"
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
using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;

namespace {

class EciesAeadHkdfPublicKeyManagerTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    ASSERT_TRUE(Registry::RegisterKeyManager(
                    absl::make_unique<AesGcmKeyManager>(), true)
                    .ok());
  }

  std::string key_type_prefix = "type.googleapis.com/";
  std::string ecies_public_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
};

TEST_F(EciesAeadHkdfPublicKeyManagerTest, testBasic) {
  EciesAeadHkdfPublicKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(EciesAeadHkdfPublicKeyManagerTest, testKeyDataErrors) {
  EciesAeadHkdfPublicKeyManager key_manager;

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
    key_data.set_type_url(ecies_public_key_type);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    EciesAeadHkdfPublicKey key;
    key.set_version(1);
    key_data.set_type_url(ecies_public_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(EciesAeadHkdfPublicKeyManagerTest, testKeyMessageErrors) {
  EciesAeadHkdfPublicKeyManager key_manager;

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

TEST_F(EciesAeadHkdfPublicKeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string context_info = "some context info";
  EciesAeadHkdfPublicKeyManager key_manager;
  EciesAeadHkdfPublicKey key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED,
      HashType::SHA256, 32).public_key();

  {  // Using Key proto.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto hybrid_encrypt = std::move(result.ValueOrDie());
    auto encrypt_result = hybrid_encrypt->Encrypt(plaintext, context_info);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(ecies_public_key_type);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto hybrid_encrypt = std::move(result.ValueOrDie());
    auto encrypt_result = hybrid_encrypt->Encrypt(plaintext, context_info);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  }
}

TEST_F(EciesAeadHkdfPublicKeyManagerTest, testNewKeyError) {
  EciesAeadHkdfPublicKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  { // Via NewKey(format_proto).
    EciesAeadHkdfKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }

  { // Via NewKey(serialized_format_proto).
    EciesAeadHkdfKeyFormat key_format;
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }

  { // Via NewKeyData(serialized_format_proto).
    EciesAeadHkdfKeyFormat key_format;
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
