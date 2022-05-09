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

#include "tink/aead/internal/cord_aes_gcm_boringssl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_test_helpers.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "openssl/err.h"
#include "include/rapidjson/document.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr absl::string_view key_128 = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kLongMessage =
    "This is some long message which will be fragmented.";
constexpr absl::string_view kAssociatedData = "Some associated data.";

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::Test;

class CordAesGcmBoringSslTest : public Test {
 protected:
  void SetUp() override {
    key_ = util::SecretDataFromStringView(absl::HexStringToBytes(key_128));
    util::StatusOr<std::unique_ptr<CordAead>> res =
        CordAesGcmBoringSsl::New(key_);
    ASSERT_THAT(res.status(), IsOk());
    cipher_ = std::move(*res);
  }

  util::SecretData key_;
  std::unique_ptr<CordAead> cipher_;
};

TEST_F(CordAesGcmBoringSslTest, EncryptDecryptCord) {
  absl::Cord message_cord = absl::Cord(kMessage);
  absl::Cord associated_data_cord = absl::Cord(kAssociatedData);
  util::StatusOr<absl::Cord> ct =
      cipher_->Encrypt(message_cord, associated_data_cord);
  ASSERT_THAT(ct.status(), IsOk());
  EXPECT_THAT(*ct, SizeIs(message_cord.size() + 12 + 16));
  util::StatusOr<absl::Cord> pt = cipher_->Decrypt(*ct, associated_data_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_EQ(*pt, message_cord.Flatten());
}

TEST_F(CordAesGcmBoringSslTest, ChunkyCordEncrypt) {
  absl::Cord message_cord =
      absl::MakeFragmentedCord(absl::StrSplit(kLongMessage, absl::ByLength(3)));
  absl::Cord associated_data_cord = absl::Cord(kAssociatedData);
  util::StatusOr<absl::Cord> ct =
      cipher_->Encrypt(message_cord, associated_data_cord);
  ASSERT_THAT(ct.status(), IsOk());
  EXPECT_THAT(*ct, SizeIs(message_cord.size() + 12 + 16));
  util::StatusOr<absl::Cord> pt = cipher_->Decrypt(*ct, associated_data_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_THAT(*pt, Eq(kLongMessage));
}

TEST_F(CordAesGcmBoringSslTest, ChunkyCordDecrypt) {
  absl::Cord message_cord = absl::Cord(kLongMessage);
  absl::Cord associated_data_cord = absl::Cord(kAssociatedData);
  util::StatusOr<absl::Cord> ct =
      cipher_->Encrypt(message_cord, associated_data_cord);
  ASSERT_THAT(ct.status(), IsOk());
  absl::Cord fragmented_ct = absl::MakeFragmentedCord(
      absl::StrSplit(ct->Flatten(), absl::ByLength(3)));
  util::StatusOr<absl::Cord> pt =
      cipher_->Decrypt(fragmented_ct, associated_data_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_THAT(*pt, Eq(kLongMessage));
}

TEST_F(CordAesGcmBoringSslTest, CanDecryptWithStringAead) {
  absl::Cord message_cord = absl::Cord(kMessage);
  absl::Cord associated_data_cord = absl::Cord(kAssociatedData);
  util::StatusOr<absl::Cord> ct =
      cipher_->Encrypt(message_cord, associated_data_cord);
  ASSERT_THAT(ct.status(), IsOk());
  EXPECT_EQ(ct->size(), message_cord.size() + 12 + 16);
  util::StatusOr<absl::Cord> pt = cipher_->Decrypt(*ct, associated_data_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_EQ(*pt, message_cord.Flatten());

  // Decrypt as string and check if it gives same result.
  util::StatusOr<std::unique_ptr<Aead>> string_aead =
      subtle::AesGcmBoringSsl::New(key_);
  ASSERT_THAT(string_aead.status(), IsOk());
  util::StatusOr<std::string> plaintext =
      (*string_aead)
          ->Decrypt(ct.value().Flatten(), associated_data_cord.Flatten());
  ASSERT_THAT(plaintext.status(), IsOk());
  EXPECT_EQ(*plaintext, kMessage);
}

TEST_F(CordAesGcmBoringSslTest, ModifiedCord) {
  absl::Cord message = absl::Cord(kMessage);
  absl::Cord ad = absl::Cord(kAssociatedData);
  util::StatusOr<absl::Cord> ct = cipher_->Encrypt(message, ad);
  ASSERT_THAT(ct.status(), IsOk());
  util::StatusOr<absl::Cord> plaintext = cipher_->Decrypt(*ct, ad);
  ASSERT_THAT(plaintext.status(), IsOk());
  EXPECT_EQ(*plaintext, message);

  // Modify the ciphertext.
  for (size_t i = 0; i < ct->size() * 8; i++) {
    std::string modified_ct = std::string(ct->Flatten());
    modified_ct[i / 8] ^= 1 << (i % 8);
    absl::Cord modified_ct_cord;
    modified_ct_cord = absl::Cord(modified_ct);
    EXPECT_THAT(cipher_->Decrypt(modified_ct_cord, ad).status(), Not(IsOk()))
        << i;
  }
  // Modify the associated data.
  for (size_t i = 0; i < ad.size() * 8; i++) {
    std::string modified_ad = std::string(ad.Flatten());
    modified_ad[i / 8] ^= 1 << (i % 8);
    absl::Cord modified_associated_data_cord;
    modified_associated_data_cord = absl::Cord(modified_ad);
    util::StatusOr<absl::Cord> decrypted =
        cipher_->Decrypt(*ct, modified_associated_data_cord);
    EXPECT_THAT(decrypted.status(), Not(IsOk())) << i << " pt: " << *decrypted;
  }
  // Truncate the ciphertext.
  for (size_t i = 0; i < ct->size(); i++) {
    std::string truncated_ct(std::string(ct->Flatten()), 0, i);
    absl::Cord truncated_ct_cord;
    truncated_ct_cord = absl::Cord(truncated_ct);
    EXPECT_THAT(cipher_->Decrypt(truncated_ct_cord, ad).status(), Not(IsOk()))
        << i;
  }
}

static std::string GetError() {
  auto err = ERR_peek_last_error();
  // Sometimes there is no error message on the stack.
  if (err == 0) {
    return "";
  }
  std::string lib(ERR_lib_error_string(err));
  std::string func(ERR_func_error_string(err));
  std::string reason(ERR_reason_error_string(err));
  return lib + ":" + func + ":" + reason;
}

// Test with test vectors from Wycheproof project.
bool WycheproofTest(const rapidjson::Document& root) {
  int errors = 0;
  for (const rapidjson::Value& test_group : root["testGroups"].GetArray()) {
    const size_t iv_size = test_group["ivSize"].GetInt();
    const size_t key_size = test_group["keySize"].GetInt();
    const size_t tag_size = test_group["tagSize"].GetInt();
    // CordAesGcmBoringSsl only supports 12-byte IVs and 16-byte
    // authentication tag. Also 24-byte keys are not supported.
    if (iv_size != 96 || tag_size != 128 || key_size == 192) {
      // Not supported
      continue;
    }
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string comment = test["comment"].GetString();
      std::string key = subtle::WycheproofUtil::GetBytes(test["key"]);
      std::string iv = subtle::WycheproofUtil::GetBytes(test["iv"]);
      std::string msg = subtle::WycheproofUtil::GetBytes(test["msg"]);
      std::string ct = subtle::WycheproofUtil::GetBytes(test["ct"]);
      std::string ad = subtle::WycheproofUtil::GetBytes(test["aad"]);
      std::string tag = subtle::WycheproofUtil::GetBytes(test["tag"]);
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string expected = test["result"].GetString();

      std::unique_ptr<CordAead> cipher = std::move(
          *CordAesGcmBoringSsl::New(util::SecretDataFromStringView(key)));
      // Convert the ciphertext to cord.
      absl::Cord ct_cord = absl::Cord(iv + ct + tag);
      absl::Cord associated_data_cord = absl::Cord(ad);
      util::StatusOr<absl::Cord> result =
          cipher->Decrypt(ct_cord, associated_data_cord);
      if (result.ok()) {
        std::string decrypted = std::string(result->Flatten());
        if (expected == "invalid") {
          ADD_FAILURE() << "Decrypted invalid ciphertext:" << id;
          errors++;
        } else if (msg != decrypted) {
          ADD_FAILURE() << "Incorrect decryption:" << id;
          errors++;
        }
      } else {
        if (expected == "valid" || expected == "acceptable") {
          ADD_FAILURE() << "Could not decrypt test with tcId:" << id
                        << " iv_size:" << iv_size << " tag_size:" << tag_size
                        << " key_size:" << key_size << " error:" << GetError();
          errors++;
        }
      }
    }
  }
  return errors == 0;
}

TEST(CordAesGcmBoringSslWycheproofTest, TestVectors) {
  std::unique_ptr<rapidjson::Document> root =
      subtle::WycheproofUtil::ReadTestVectors("aes_gcm_test.json");
  ASSERT_TRUE(WycheproofTest(*root));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
