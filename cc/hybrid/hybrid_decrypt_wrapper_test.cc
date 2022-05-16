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

#include "tink/hybrid/hybrid_decrypt_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/hybrid_decrypt.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::DummyHybridDecrypt;
using ::crypto::tink::test::DummyHybridEncrypt;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

class HybridDecryptSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(HybridDecryptSetWrapperTest, Basic) {
  { // hybrid_decrypt_set is nullptr.
    auto hybrid_decrypt_result =
        HybridDecryptWrapper().Wrap(nullptr);
    EXPECT_FALSE(hybrid_decrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal,
              hybrid_decrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(hybrid_decrypt_result.status().message()));
  }

  { // hybrid_decrypt_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<HybridDecrypt>>
        hybrid_decrypt_set(new PrimitiveSet<HybridDecrypt>());
    auto hybrid_decrypt_result = HybridDecryptWrapper().Wrap(
        std::move(hybrid_decrypt_set));
    EXPECT_FALSE(hybrid_decrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
        hybrid_decrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(hybrid_decrypt_result.status().message()));
  }

  { // Correct hybrid_decrypt_set;
    KeysetInfo::KeyInfo* key;
    KeysetInfo keyset;

    uint32_t key_id_0 = 1234543;
    key = keyset.add_key_info();
    key->set_output_prefix_type(OutputPrefixType::RAW);
    key->set_key_id(key_id_0);
    key->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_1 = 726329;
    key = keyset.add_key_info();
    key->set_output_prefix_type(OutputPrefixType::LEGACY);
    key->set_key_id(key_id_1);
    key->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_2 = 7213743;
    key = keyset.add_key_info();
    key->set_output_prefix_type(OutputPrefixType::TINK);
    key->set_key_id(key_id_2);
    key->set_status(KeyStatusType::ENABLED);

    std::string hybrid_name_0 = "hybrid_0";
    std::string hybrid_name_1 = "hybrid_1";
    std::string hybrid_name_2 = "hybrid_2";
    std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set(
        new PrimitiveSet<HybridDecrypt>());
    std::unique_ptr<HybridDecrypt> hybrid_decrypt(
        new DummyHybridDecrypt(hybrid_name_0));
    auto entry_result = hybrid_decrypt_set->AddPrimitive(
        std::move(hybrid_decrypt), keyset.key_info(0));
    ASSERT_TRUE(entry_result.ok());
    hybrid_decrypt.reset(new DummyHybridDecrypt(hybrid_name_1));
    entry_result = hybrid_decrypt_set->AddPrimitive(std::move(hybrid_decrypt),
                                                    keyset.key_info(1));
    ASSERT_TRUE(entry_result.ok());
    std::string prefix_id_1 = entry_result.value()->get_identifier();
    hybrid_decrypt.reset(new DummyHybridDecrypt(hybrid_name_2));
    entry_result = hybrid_decrypt_set->AddPrimitive(std::move(hybrid_decrypt),
                                                    keyset.key_info(2));
    ASSERT_TRUE(entry_result.ok());
    // The last key is the primary.
    ASSERT_THAT(hybrid_decrypt_set->set_primary(entry_result.value()), IsOk());

    // Wrap hybrid_decrypt_set and test the resulting HybridDecrypt.
    auto hybrid_decrypt_result = HybridDecryptWrapper().Wrap(
        std::move(hybrid_decrypt_set));
    EXPECT_TRUE(hybrid_decrypt_result.ok()) << hybrid_decrypt_result.status();
    hybrid_decrypt = std::move(hybrid_decrypt_result.value());
    std::string plaintext = "some_plaintext";
    std::string context_info = "some_context";

    {  // RAW key
      std::string ciphertext = DummyHybridEncrypt(hybrid_name_0)
                                   .Encrypt(plaintext, context_info)
                                   .value();
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
      EXPECT_EQ(plaintext, decrypt_result.value());
    }

    {  // No ciphertext prefix.
      std::string ciphertext = plaintext + hybrid_name_1;
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_FALSE(decrypt_result.ok());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument,
                decrypt_result.status().code());
      EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                          std::string(decrypt_result.status().message()));
    }

    {  // Correct ciphertext prefix.
      std::string ciphertext =
          prefix_id_1 + DummyHybridEncrypt(hybrid_name_1)
                            .Encrypt(plaintext, context_info)
                            .value();
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
      EXPECT_EQ(plaintext, decrypt_result.value());
    }

    {  // Bad ciphertext.
      std::string ciphertext = "some bad ciphertext";
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_FALSE(decrypt_result.ok());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument,
          decrypt_result.status().code());
      EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                          std::string(decrypt_result.status().message()));
    }
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
