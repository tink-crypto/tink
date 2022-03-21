// Copyright 2017 Google LLC
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
#include "tink/aead/aead_factory.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/crypto_format.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;


namespace crypto {
namespace tink {
namespace {

class AeadFactoryTest : public ::testing::Test {
};

TEST_F(AeadFactoryTest, testBasic) {
  Keyset keyset;
  auto aead_result =
      AeadFactory::GetPrimitive(*TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, aead_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "at least one key",
                      std::string(aead_result.status().message()));
}

TEST_F(AeadFactoryTest, testPrimitive) {
  // Prepare a template for generating keys for a Keyset.
  std::string key_type = AesGcmKeyManager().get_key_type();

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);

  // Prepare a Keyset.
  Keyset keyset;
  uint32_t key_id_1 = 1234543;
  AesGcmKey new_key = AesGcmKeyManager().CreateKey(key_format).value();
  AddTinkKey(key_type, key_id_1, new_key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  new_key = AesGcmKeyManager().CreateKey(key_format).value();
  AddRawKey(key_type, key_id_2, new_key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  new_key = AesGcmKeyManager().CreateKey(key_format).value();
  AddTinkKey(key_type, key_id_3, new_key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Initialize the registry.
  ASSERT_TRUE(AeadConfig::Register().ok());;

  // Create a KeysetHandle and use it with the factory.
  auto aead_result =
      AeadFactory::GetPrimitive(*TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  auto aead = std::move(aead_result.value());

  // Test the resulting Aead-instance.
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.value();
  std::string prefix =
      CryptoFormat::GetOutputPrefix(KeyInfoFromKey(keyset.key(2))).value();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, prefix, ciphertext);

  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.value());

  decrypt_result = aead->Decrypt("some bad ciphertext", aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument,
            decrypt_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                      std::string(decrypt_result.status().message()));

  // Create raw ciphertext with 2nd key, and decrypt with Aead-instance.
  AesGcmKey raw_key;
  EXPECT_TRUE(raw_key.ParseFromString(keyset.key(1).key_data().value()));
  auto raw_aead =
      std::move(AesGcmKeyManager().GetPrimitive<Aead>(raw_key).value());
  std::string raw_ciphertext = raw_aead->Encrypt(plaintext, aad).value();
  decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.value());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
