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

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::HasSubstr;
using ::testing::IsSubstring;
using ::testing::Not;

void PopulateKeyInfo(KeysetInfo::KeyInfo* key_info, uint32_t key_id,
                     OutputPrefixType out_prefix_type, KeyStatusType status) {
  key_info->set_output_prefix_type(out_prefix_type);
  key_info->set_key_id(key_id);
  key_info->set_status(status);
}

TEST(AeadSetWrapperTest, WrapNullptr) {
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead = wrapper.Wrap(nullptr);
  EXPECT_THAT(aead.status(), Not(IsOk()));
  EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInternal));
  EXPECT_PRED_FORMAT2(IsSubstring, "non-NULL",
                      std::string(aead.status().message()));
}

TEST(AeadSetWrapperTest, WrapEmpty) {
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead =
      wrapper.Wrap(absl::make_unique<PrimitiveSet<Aead>>());
  EXPECT_THAT(aead.status(), Not(IsOk()));
  EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "no primary",
                      std::string(aead.status().message()));
}

TEST(AeadSetWrapperTest, Basic) {
  KeysetInfo keyset_info;
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/1234543,
                  OutputPrefixType::TINK,
                  /*status=*/KeyStatusType::ENABLED);
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/726329,
                  OutputPrefixType::LEGACY,
                  /*status=*/KeyStatusType::ENABLED);
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/7213743,
                  OutputPrefixType::TINK,
                  /*status=*/KeyStatusType::ENABLED);

  std::string aead_name_0 = "aead0";
  std::string aead_name_1 = "aead1";
  std::string aead_name_2 = "aead2";
  auto aead_set = absl::make_unique<PrimitiveSet<Aead>>();
  std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>(aead_name_0);
  util::StatusOr<PrimitiveSet<Aead>::Entry<Aead>*> aead_entry =
      aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(0));
  EXPECT_THAT(aead_entry.status(), IsOk());
  aead = absl::make_unique<DummyAead>(aead_name_1);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(1));
  EXPECT_THAT(aead_entry.status(), IsOk());
  aead = absl::make_unique<DummyAead>(aead_name_2);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(2));
  EXPECT_THAT(aead_entry.status(), IsOk());
  // The last key is the primary.
  EXPECT_THAT(aead_set->set_primary(*aead_entry), IsOk());

  // Wrap aead_set and test the resulting Aead.
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead_result =
      wrapper.Wrap(std::move(aead_set));
  EXPECT_THAT(aead_result.status(), IsOk());
  aead = std::move(*aead_result);
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  util::StatusOr<std::string> encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_THAT(encrypt_result.status(), IsOk());
  std::string ciphertext = *encrypt_result;
  EXPECT_PRED_FORMAT2(testing::IsSubstring, aead_name_2, ciphertext);

  util::StatusOr<std::string> resulting_plaintext =
      aead->Decrypt(ciphertext, aad);
  EXPECT_THAT(resulting_plaintext.status(), IsOk());
  EXPECT_EQ(*resulting_plaintext, plaintext);

  resulting_plaintext = aead->Decrypt("some bad ciphertext", aad);
  EXPECT_THAT(resulting_plaintext.status(), Not(IsOk()));
  EXPECT_THAT(resulting_plaintext.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "decryption failed",
                      std::string(resulting_plaintext.status().message()));
}

TEST(AeadSetWrapperTest, DecryptNonPrimary) {
  KeysetInfo keyset_info;
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/1234543,
                  OutputPrefixType::TINK,
                  /*status=*/KeyStatusType::ENABLED);
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/726329,
                  OutputPrefixType::LEGACY,
                  /*status=*/KeyStatusType::ENABLED);
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/7213743,
                  OutputPrefixType::TINK,
                  /*status=*/KeyStatusType::ENABLED);

  std::string aead_name_0 = "aead0";
  std::string aead_name_1 = "aead1";
  std::string aead_name_2 = "aead2";
  std::unique_ptr<PrimitiveSet<Aead>> aead_set(new PrimitiveSet<Aead>());
  std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>(aead_name_0);

  // Encrypt some message with the first aead.s
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  util::StatusOr<std::string> ciphertext = aead->Encrypt(plaintext, aad);
  EXPECT_THAT(ciphertext.status(), IsOk());
  util::StatusOr<PrimitiveSet<Aead>::Entry<Aead>*> aead_entry =
      aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(0));
  ASSERT_THAT(aead_entry.status(), IsOk());
  EXPECT_THAT(aead_set->set_primary(*aead_entry), IsOk());

  // The complete ciphertext is of the form: | key_id | ciphertext |.
  std::string complete_ciphertext =
      absl::StrCat(aead_set->get_primary()->get_identifier(), *ciphertext);

  aead = absl::make_unique<DummyAead>(aead_name_1);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(1));
  EXPECT_THAT(aead_entry.status(), IsOk());
  aead = absl::make_unique<DummyAead>(aead_name_2);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(2));
  EXPECT_THAT(aead_entry.status(), IsOk());
  // The last key is the primary.
  EXPECT_THAT(aead_set->set_primary(*aead_entry), IsOk());

  // Wrap aead_set and test the resulting Aead.
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead_wrapped =
      wrapper.Wrap(std::move(aead_set));
  EXPECT_THAT(aead_wrapped.status(), IsOk());
  aead = std::move(*aead_wrapped);
  EXPECT_THAT(complete_ciphertext, HasSubstr(aead_name_0));

  // Primary key is different from the one we used to encrypt. This
  // should still be decryptable as we have the correct key in the set.
  util::StatusOr<std::string> decrypted_plaintext =
      aead->Decrypt(complete_ciphertext, aad);
  EXPECT_THAT(decrypted_plaintext.status(), IsOk());
}
}  // namespace
}  // namespace tink
}  // namespace crypto
