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

#include "tink/daead/deterministic_aead_wrapper.h"

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/deterministic_aead.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::DummyDeterministicAead;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

class DeterministicAeadSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(DeterministicAeadSetWrapperTest, testBasic) {
  {  // daead_set is nullptr.
    auto daead_result =
        DeterministicAeadWrapper().Wrap(nullptr);
    EXPECT_FALSE(daead_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal, daead_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(daead_result.status().message()));
  }

  {  // daead_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<DeterministicAead>> daead_set(
        new PrimitiveSet<DeterministicAead>());
    auto daead_result =
        DeterministicAeadWrapper().Wrap(std::move(daead_set));
    EXPECT_FALSE(daead_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              daead_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(daead_result.status().message()));
  }

  {  // Correct daead_set;
    KeysetInfo::KeyInfo* key_info;
    KeysetInfo keyset_info;

    uint32_t key_id_0 = 1234543;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_key_id(key_id_0);
    key_info->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_1 = 726329;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
    key_info->set_key_id(key_id_1);
    key_info->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_2 = 7213743;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_key_id(key_id_2);
    key_info->set_status(KeyStatusType::ENABLED);

    std::string daead_name_0 = "daead0";
    std::string daead_name_1 = "daead1";
    std::string daead_name_2 = "daead2";
    std::unique_ptr<PrimitiveSet<DeterministicAead>> daead_set(
        new PrimitiveSet<DeterministicAead>());
    std::unique_ptr<DeterministicAead> daead(
        new DummyDeterministicAead(daead_name_0));
    auto entry_result =
        daead_set->AddPrimitive(std::move(daead), keyset_info.key_info(0));
    ASSERT_TRUE(entry_result.ok());
    daead = absl::make_unique<DummyDeterministicAead>(daead_name_1);
    entry_result =
        daead_set->AddPrimitive(std::move(daead), keyset_info.key_info(1));
    ASSERT_TRUE(entry_result.ok());
    daead = absl::make_unique<DummyDeterministicAead>(daead_name_2);
    entry_result =
        daead_set->AddPrimitive(std::move(daead), keyset_info.key_info(2));
    ASSERT_TRUE(entry_result.ok());
    // The last key is the primary.
    ASSERT_THAT(daead_set->set_primary(entry_result.ValueOrDie()), IsOk());

    // Wrap daead_set and test the resulting DeterministicAead.
    auto daead_result =
        DeterministicAeadWrapper().Wrap(std::move(daead_set));
    EXPECT_TRUE(daead_result.ok()) << daead_result.status();
    daead = std::move(daead_result.ValueOrDie());
    std::string plaintext = "some_plaintext";
    std::string aad = "some_aad";

    auto encrypt_result = daead->EncryptDeterministically(plaintext, aad);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    std::string ciphertext = encrypt_result.ValueOrDie();
    EXPECT_PRED_FORMAT2(testing::IsSubstring, daead_name_2, ciphertext);

    auto decrypt_result = daead->DecryptDeterministically(ciphertext, aad);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());

    decrypt_result =
        daead->DecryptDeterministically("some bad ciphertext", aad);
    EXPECT_FALSE(decrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              decrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                        std::string(decrypt_result.status().message()));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
