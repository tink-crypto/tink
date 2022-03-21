// Copyright 2020 Google LLC
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

#include "tink/aead/cord_aead_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/cord_test_helpers.h"
#include "absl/strings/str_split.h"
#include "tink/aead/cord_aead.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::DummyCordAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(AeadSetWrapperTest, WrapNullptr) {
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(nullptr);
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, aead_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      std::string(aead_result.status().message()));
}

TEST(AeadSetWrapperTest, WrapEmpty) {
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(absl::make_unique<PrimitiveSet<CordAead>>());
  EXPECT_FALSE(aead_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, aead_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      std::string(aead_result.status().message()));
}

std::unique_ptr<PrimitiveSet<CordAead>> setup_keyset() {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  uint32_t key_id_0 = 1234543;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_0);
  key_info->set_status(KeyStatusType::ENABLED);
  std::string aead_name_0 = "aead0";
  std::unique_ptr<PrimitiveSet<CordAead>> aead_set(
      new PrimitiveSet<CordAead>());
  std::unique_ptr<CordAead> aead =
      absl::make_unique<DummyCordAead>(aead_name_0);
  auto entry_result =
      aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(0));
  auto aead_set_result = aead_set->set_primary(entry_result.value());
  return aead_set;
}

TEST(AeadSetWrapperTest, WrapperEncryptDecrypt) {
  // Wrap aead_set and test the resulting Aead.
  auto aead_set = setup_keyset();
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(std::move(aead_set));
  ASSERT_THAT(aead_result.status(), IsOk());
  auto aead = std::move(aead_result.value());
  absl::Cord plaintext;
  plaintext.Append("some_plaintext");
  absl::Cord aad;
  aad.Append("some_aad");

  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  absl::Cord ciphertext = encrypt_result.value();

  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST(AeadSetWrapperTest, WrapperEncryptDecryptMultipleKeys) {
  // Wrap aead_set and test the resulting Aead.
  auto aead_set = setup_keyset();

  // Encrypt with the primary key
  absl::Cord plaintext;
  plaintext.Append("some_plaintext");
  absl::Cord aad;
  aad.Append("some_aad");
  auto encrypt_result =
      aead_set->get_primary()->get_primitive().Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  absl::Cord ciphertext;
  ciphertext.Append(aead_set->get_primary()->get_identifier());
  ciphertext.Append(encrypt_result.value());

  // Add a second key
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;
  uint32_t key_id = 42;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id);
  key_info->set_status(KeyStatusType::ENABLED);
  std::string aead_name = "aead1";
  std::unique_ptr<CordAead> aead = absl::make_unique<DummyCordAead>(aead_name);
  auto entry_result =
      aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(0));
  EXPECT_TRUE(entry_result.ok()) << entry_result.status();

  // Wrap the primitive set
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(std::move(aead_set));
  ASSERT_THAT(aead_result.status(), IsOk());
  aead = std::move(aead_result.value());

  // Encrypt with the wrapped AEAD and check if result was equal to the
  // encryption with the primary key.
  auto encrypt_wrap_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_wrap_result.ok()) << encrypt_wrap_result.status();
  EXPECT_EQ(ciphertext, encrypt_wrap_result.value());
}

TEST(AeadSetWrapperTest, WrapperEncryptDecryptManyChunks) {
  // Wrap aead_set and test the resulting Aead.
  auto aead_set = setup_keyset();
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(std::move(aead_set));
  ASSERT_THAT(aead_result.status(), IsOk());
  auto aead = std::move(aead_result.value());

  std::string plaintext = "";
  for (int i = 0; i < 1000; i++) {
    plaintext += "chunk" + std::to_string(i);
  }
  absl::Cord plaintext_cord =
      absl::MakeFragmentedCord(absl::StrSplit(plaintext, absl::ByLength(5)));
  absl::Cord aad;
  aad.Append("some_aad");

  auto encrypt_result = aead->Encrypt(plaintext_cord, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  absl::Cord ciphertext = encrypt_result.value();

  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST(AeadSetWrapperTest, WrapperEncryptBadDecrypt) {
  // Wrap aead_set and test the resulting Aead.
  auto aead_set = setup_keyset();
  CordAeadWrapper wrapper;
  auto aead_result = wrapper.Wrap(std::move(aead_set));
  ASSERT_THAT(aead_result.status(), IsOk());
  auto aead = std::move(aead_result.value());
  absl::Cord plaintext;
  plaintext.Append("some_plaintext");
  absl::Cord aad;
  aad.Append("some_aad");

  absl::Cord bad_ciphertext;
  bad_ciphertext.Append("some bad ciphertext");
  auto decrypt_result = aead->Decrypt(bad_ciphertext, aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, decrypt_result.status().code());
  EXPECT_THAT(decrypt_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("decryption failed")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
