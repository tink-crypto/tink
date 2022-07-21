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
#include "tink/daead/deterministic_aead_factory.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/crypto_format.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/deterministic_aead.h"
#include "tink/internal/key_info.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/aes_siv.pb.h"

using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::AesSivKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;


namespace crypto {
namespace tink {
namespace {

class DeterministicAeadFactoryTest : public ::testing::Test {};

TEST_F(DeterministicAeadFactoryTest, testBasic) {
  Keyset keyset;
  auto daead_result = DeterministicAeadFactory::GetPrimitive(
      *TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_FALSE(daead_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, daead_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "at least one key",
                      std::string(daead_result.status().message()));
}

TEST_F(DeterministicAeadFactoryTest, testPrimitive) {
  // Prepare a template for generating keys for a Keyset.
  AesSivKeyManager key_type_manager;
  auto key_manager =
      internal::MakeKeyManager<DeterministicAead>(&key_type_manager);
  const KeyFactory& key_factory = key_manager->get_key_factory();
  std::string key_type = key_manager->get_key_type();

  AesSivKeyFormat key_format;
  key_format.set_key_size(64);

  // Prepare a Keyset.
  Keyset keyset;
  uint32_t key_id_1 = 1234543;
  auto new_key = std::move(key_factory.NewKey(key_format).value());
  AddTinkKey(key_type, key_id_1, *new_key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  new_key = std::move(key_factory.NewKey(key_format).value());
  AddRawKey(key_type, key_id_2, *new_key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  new_key = std::move(key_factory.NewKey(key_format).value());
  AddTinkKey(key_type, key_id_3, *new_key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Initialize the registry.
  ASSERT_TRUE(DeterministicAeadConfig::Register().ok());

  // Create a KeysetHandle and use it with the factory.
  auto daead_result = DeterministicAeadFactory::GetPrimitive(
      *TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_TRUE(daead_result.ok()) << daead_result.status();
  auto daead = std::move(daead_result.value());

  // Test the resulting DeterministicAead-instance.
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  auto encrypt_result = daead->EncryptDeterministically(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.value();
  std::string prefix =
      CryptoFormat::GetOutputPrefix(KeyInfoFromKey(keyset.key(2))).value();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, prefix, ciphertext);

  auto decrypt_result = daead->DecryptDeterministically(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.value());

  decrypt_result = daead->DecryptDeterministically("some bad ciphertext", aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument,
            decrypt_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                      std::string(decrypt_result.status().message()));

  // Create raw ciphertext with 2nd key, and decrypt
  // with DeterministicAead-instance.
  auto raw_daead =
      std::move(key_manager->GetPrimitive(keyset.key(1).key_data()).value());
  std::string raw_ciphertext =
      raw_daead->EncryptDeterministically(plaintext, aad).value();
  decrypt_result = daead->DecryptDeterministically(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.value());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
