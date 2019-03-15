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

#include "tink/aead/aead_wrapper.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

using crypto::tink::test::DummyAead;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(AeadSetWrapperTest, WrapNullptr) {
  AeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(nullptr);
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(util::error::INTERNAL, aead_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      aead_result.status().error_message());
}

TEST(AeadSetWrapperTest, WrapEmpty) {
  AeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(absl::make_unique<PrimitiveSet<Aead>>());
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, aead_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      aead_result.status().error_message());
}

TEST(AeadSetWrapperTest, Basic) {
  Keyset::Key* key;
  Keyset keyset;

  uint32_t key_id_0 = 1234543;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_0);
  key->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_1 = 726329;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::LEGACY);
  key->set_key_id(key_id_1);
  key->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_2);
  key->set_status(KeyStatusType::ENABLED);

  std::string aead_name_0 = "aead0";
  std::string aead_name_1 = "aead1";
  std::string aead_name_2 = "aead2";
  std::unique_ptr<PrimitiveSet<Aead>> aead_set(new PrimitiveSet<Aead>());
  std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>(aead_name_0);
  auto entry_result = aead_set->AddPrimitive(std::move(aead), keyset.key(0));
  ASSERT_TRUE(entry_result.ok());
  aead = absl::make_unique<DummyAead>(aead_name_1);
  entry_result = aead_set->AddPrimitive(std::move(aead), keyset.key(1));
  ASSERT_TRUE(entry_result.ok());
  aead = absl::make_unique<DummyAead>(aead_name_2);
  entry_result = aead_set->AddPrimitive(std::move(aead), keyset.key(2));
  ASSERT_TRUE(entry_result.ok());
  // The last key is the primary.
  aead_set->set_primary(entry_result.ValueOrDie());

  // Wrap aead_set and test the resulting Aead.
  AeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(std::move(aead_set));
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  aead = std::move(aead_result.ValueOrDie());
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.ValueOrDie();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, aead_name_2, ciphertext);

  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());

  decrypt_result = aead->Decrypt("some bad ciphertext", aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                      decrypt_result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
