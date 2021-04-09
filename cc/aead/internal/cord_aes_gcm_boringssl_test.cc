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

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/cord_test_helpers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "openssl/err.h"
#include "include/rapidjson/document.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;

namespace {

TEST(CordAesGcmBoringSslTest, EncryptDecryptCord) {
  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = CordAesGcmBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  const std::string message = "Some data to encrypt.";
  const std::string aad = "Some data to authenticate.";

  absl::Cord message_cord = absl::Cord(message);
  absl::Cord aad_cord = absl::Cord(aad);

  auto ct = cipher->Encrypt(message_cord, aad_cord);
  EXPECT_THAT(ct.status(), IsOk());
  EXPECT_EQ(ct.ValueOrDie().size(), message_cord.size() + 12 + 16);

  auto pt = cipher->Decrypt(ct.ValueOrDie(), aad_cord);
  EXPECT_THAT(pt.status(), IsOk());
  EXPECT_EQ(pt.ValueOrDie(), message_cord.Flatten());
}

TEST(CordAesGcmBoringSslTest, ChunkyCordEncrypt) {
  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = CordAesGcmBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "This is some long message which will be fragmented.";
  const std::string aad = "Some data to authenticate.";

  absl::Cord message_cord =
      absl::MakeFragmentedCord(absl::StrSplit(message, absl::ByLength(3)));
  absl::Cord aad_cord = absl::Cord(aad);

  auto ct = cipher->Encrypt(message_cord, aad_cord);
  ASSERT_THAT(ct.status(), IsOk());
  EXPECT_EQ(ct.ValueOrDie().size(), message_cord.size() + 12 + 16);

  auto pt = cipher->Decrypt(ct.ValueOrDie(), aad_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_THAT(pt.ValueOrDie(), Eq(message));
}

TEST(CordAesGcmBoringSslTest, ChunkyCordDecrypt) {
  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = CordAesGcmBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "This is some long message which will be fragmented.";
  const std::string aad = "Some data to authenticate.";

  absl::Cord message_cord = absl::Cord(message);
  absl::Cord aad_cord = absl::Cord(aad);

  auto ct = cipher->Encrypt(message_cord, aad_cord);
  ASSERT_THAT(ct.status(), IsOk());

  auto fragmented_ct = absl::MakeFragmentedCord(
      absl::StrSplit(ct.ValueOrDie().Flatten(), absl::ByLength(3)));

  auto pt = cipher->Decrypt(fragmented_ct, aad_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_THAT(pt.ValueOrDie(), Eq(message));
}

TEST(CordAesGcmBoringSslTest, SameResultAsString) {
  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = CordAesGcmBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  const std::string message = "Some data to encrypt.";
  const std::string aad = "Some data to authenticate.";

  absl::Cord message_cord = absl::Cord(message);
  absl::Cord aad_cord = absl::Cord(aad);

  auto ct = cipher->Encrypt(message_cord, aad_cord);
  ASSERT_THAT(ct.status(), IsOk());
  EXPECT_EQ(ct.ValueOrDie().size(), message_cord.size() + 12 + 16);

  auto pt = cipher->Decrypt(ct.ValueOrDie(), aad_cord);
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_EQ(pt.ValueOrDie(), message_cord.Flatten());

  // Decrypt as string and check if it gives same result
  auto res_string = subtle::AesGcmBoringSsl::New(key);
  ASSERT_THAT(res_string.status(), IsOk());
  auto cipher_string = std::move(res_string.ValueOrDie());

  auto pt_string =
      cipher_string->Decrypt(ct.ValueOrDie().Flatten(), aad_cord.Flatten());
  ASSERT_THAT(pt.status(), IsOk());
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(CordAesGcmBoringSslTest, ModifiedCord) {
  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(CordAesGcmBoringSsl::New(key).ValueOrDie());
  absl::Cord message = absl::Cord("Some data to encrypt.");
  absl::Cord aad = absl::Cord("Some data to authenticate.");
  absl::Cord ct = cipher->Encrypt(message, aad).ValueOrDie();
  EXPECT_TRUE(cipher->Decrypt(ct, aad).ok());
  // Modify the ciphertext
  for (size_t i = 0; i < ct.size() * 8; i++) {
    std::string modified_ct = std::string(ct.Flatten());
    modified_ct[i / 8] ^= 1 << (i % 8);
    absl::Cord modified_ct_cord;
    modified_ct_cord = absl::Cord(modified_ct);
    EXPECT_FALSE(cipher->Decrypt(modified_ct_cord, aad).ok()) << i;
  }
  // Modify the additional data
  for (size_t i = 0; i < aad.size() * 8; i++) {
    std::string modified_aad = std::string(aad.Flatten());
    modified_aad[i / 8] ^= 1 << (i % 8);
    absl::Cord modified_aad_cord;
    modified_aad_cord = absl::Cord(modified_aad);
    auto decrypted = cipher->Decrypt(ct, modified_aad_cord);
    EXPECT_FALSE(decrypted.ok()) << i << " pt:" << decrypted.ValueOrDie();
  }
  // Truncate the ciphertext
  for (size_t i = 0; i < ct.size(); i++) {
    std::string truncated_ct(std::string(ct.Flatten()), 0, i);
    absl::Cord truncated_ct_cord;
    truncated_ct_cord = absl::Cord(truncated_ct);
    EXPECT_FALSE(cipher->Decrypt(truncated_ct_cord, aad).ok()) << i;
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
    // CordAesGcmBoringSsl only supports 12-byte IVs and 16-byte authentication
    // tag. Also 24-byte keys are not supported.
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
      std::string aad = subtle::WycheproofUtil::GetBytes(test["aad"]);
      std::string tag = subtle::WycheproofUtil::GetBytes(test["tag"]);
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string expected = test["result"].GetString();
      auto cipher = std::move(
          CordAesGcmBoringSsl::New(util::SecretDataFromStringView(key))
              .ValueOrDie());
      // Convert to cord
      absl::Cord ct_cord = absl::Cord(iv + ct + tag);
      absl::Cord aad_cord = absl::Cord(aad);
      auto result = cipher->Decrypt(ct_cord, aad_cord);
      bool success = result.ok();
      if (success) {
        std::string decrypted = std::string(result.ValueOrDie().Flatten());
        if (expected == "invalid") {
          ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
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

TEST(CordAesGcmBoringSslTest, TestVectors) {
  std::unique_ptr<rapidjson::Document> root =
      subtle::WycheproofUtil::ReadTestVectors("aes_gcm_test.json");
  ASSERT_TRUE(WycheproofTest(*root));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
