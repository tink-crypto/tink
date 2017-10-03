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
#include "cc/aead/aead_factory.h"

#include "cc/aead.h"
#include "cc/crypto_format.h"
#include "cc/keyset_handle.h"
#include "cc/aead/aead_config.h"
#include "cc/aead/aes_gcm_key_manager.h"
#include "cc/util/status.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using crypto::tink::test::GetKeysetHandle;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {
namespace {

class AeadFactoryTest : public ::testing::Test {
};

TEST_F(AeadFactoryTest, testBasic) {
  Keyset keyset;
  auto aead_result = AeadFactory::GetPrimitive(*GetKeysetHandle(keyset));
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, aead_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "at least one key",
                      aead_result.status().error_message());
}

TEST_F(AeadFactoryTest, testPrimitive) {
  // Prepare a template for generating keys for a Keyset.
  AesGcmKeyManager key_manager;
  std::string key_type = key_manager.get_key_type();

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  KeyTemplate key_template;
  key_template.set_type_url(key_type);
  key_template.set_value(key_format.SerializeAsString());

  // Prepare a Keyset.
  Keyset keyset;
  uint32_t key_id_1 = 1234543;
  auto new_key = std::move(key_manager.NewKey(key_template).ValueOrDie());
  AddTinkKey(key_type, key_id_1, *new_key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  new_key = std::move(key_manager.NewKey(key_template).ValueOrDie());
  AddRawKey(key_type, key_id_2, *new_key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  new_key = std::move(key_manager.NewKey(key_template).ValueOrDie());
  AddTinkKey(key_type, key_id_3, *new_key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Initialize the registry.
  ASSERT_TRUE(AeadConfig::RegisterStandardKeyTypes().ok());;

  // Create a KeysetHandle and use it with the factory.
  auto aead_result = AeadFactory::GetPrimitive(*GetKeysetHandle(keyset));
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  // Test the resulting Aead-instance.
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.ValueOrDie();
  std::string prefix =
      CryptoFormat::get_output_prefix(keyset.key(2)).ValueOrDie();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, prefix, ciphertext);

  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());

  decrypt_result = aead->Decrypt("some bad ciphertext", aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                      decrypt_result.status().error_message());

  // Create raw ciphertext with 2nd key, and decrypt with Aead-instance.
  auto raw_aead = std::move(
      key_manager.GetPrimitive(keyset.key(1).key_data()).ValueOrDie());
  std::string raw_ciphertext = raw_aead->Encrypt(plaintext, aad).ValueOrDie();
  decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
