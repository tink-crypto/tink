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

#include "tink/subtle/aes_gcm_boringssl.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/err.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAad = "Some data to authenticate.";
constexpr absl::string_view kKey128 = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kKey256 =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Not;
using ::testing::Test;

class AesGcmBoringSslTest : public Test {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled() && !FIPS_mode()) {
      GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                      "unavailable.";
    }

    util::SecretData key =
        util::SecretDataFromStringView(absl::HexStringToBytes(kKey128));
    util::StatusOr<std::unique_ptr<Aead>> cipher = AesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher.status(), IsOk());
    cipher_ = std::move(*cipher);
  }
  std::unique_ptr<Aead> cipher_;
};

TEST_F(AesGcmBoringSslTest, BasicEncryptDecrypt) {
  util::StatusOr<std::string> ciphertext = cipher_->Encrypt(kMessage, kAad);
  ASSERT_THAT(ciphertext.status(), IsOk());
  EXPECT_EQ(ciphertext->size(), kMessage.size() + 12 + 16);
  util::StatusOr<std::string> plaintext = cipher_->Decrypt(*ciphertext, kAad);
  ASSERT_THAT(plaintext.status(), IsOk());
  EXPECT_EQ(*plaintext, kMessage);
}

TEST_F(AesGcmBoringSslTest, ModifyMessageAndAad) {
  std::string ciphertext = cipher_->Encrypt(kMessage, kAad).ValueOrDie();
  ASSERT_THAT(cipher_->Decrypt(ciphertext, kAad).status(), IsOk());
  // Modify the ciphertext.
  for (size_t i = 0; i < ciphertext.size() * 8; i++) {
    std::string modified_ct = ciphertext;
    modified_ct[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT(cipher_->Decrypt(modified_ct, kAad).status(), Not(IsOk())) << i;
  }
  // Modify the additional data.
  for (size_t i = 0; i < kAad.size() * 8; i++) {
    std::string modified_aad = std::string(kAad);
    modified_aad[i / 8] ^= 1 << (i % 8);
    auto decrypted = cipher_->Decrypt(ciphertext, modified_aad);
    EXPECT_THAT(decrypted.status(), Not(IsOk())) << i << " pt:" << *decrypted;
  }
  // Truncate the ciphertext.
  for (size_t i = 0; i < ciphertext.size(); i++) {
    std::string truncated_ct(ciphertext, 0, i);
    EXPECT_THAT(cipher_->Decrypt(truncated_ct, kAad).status(), Not(IsOk()))
        << i;
  }
}

void TestDecryptWithEmptyAad(Aead* cipher, absl::string_view ct,
                             absl::string_view message) {
  {  // AAD is a null string_view.
    const absl::string_view aad;
    util::StatusOr<std::string> plaintext = cipher->Decrypt(ct, aad);
    EXPECT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(message, *plaintext);
  }
  {  // AAD is a an empty string.
    util::StatusOr<std::string> plaintext = cipher->Decrypt(ct, "");
    EXPECT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(message, *plaintext);
  }
  {  // AAD is a default constructed string_view.
    util::StatusOr<std::string> plaintext =
        cipher->Decrypt(ct, absl::string_view());
    EXPECT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(message, *plaintext);
  }
}

TEST_F(AesGcmBoringSslTest, AadEmptyVersusNullStringView) {
  {
    // AAD is a null string_view.
    const absl::string_view aad;
    auto ciphertext = cipher_->Encrypt(kMessage, aad);
    EXPECT_THAT(ciphertext.status(), IsOk());
    TestDecryptWithEmptyAad(cipher_.get(), *ciphertext, kMessage);
  }
  {  // AAD is a an empty string.
    auto ciphertext = cipher_->Encrypt(kMessage, "");
    EXPECT_THAT(ciphertext.status(), IsOk());
    TestDecryptWithEmptyAad(cipher_.get(), *ciphertext, kMessage);
  }
  {  // AAD is a default constructed string_view.
    auto ciphertext = cipher_->Encrypt(kMessage, absl::string_view());
    EXPECT_THAT(ciphertext.status(), IsOk());
    TestDecryptWithEmptyAad(cipher_.get(), *ciphertext, kMessage);
  }
}

TEST_F(AesGcmBoringSslTest, MessageEmptyVersusNullStringView) {
  {  // Message is a null string_view.
    const absl::string_view message;
    util::StatusOr<std::string> ciphertext = cipher_->Encrypt(message, kAad);
    ASSERT_THAT(ciphertext.status(), IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, kAad);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Message is an empty string.
    const std::string message = "";
    util::StatusOr<std::string> ciphertext = cipher_->Encrypt(message, kAad);
    ASSERT_THAT(ciphertext.status(), IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, kAad);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Message is a default constructed string_view.
    util::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(absl::string_view(), kAad);
    ASSERT_THAT(ciphertext.status(), IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, kAad);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, "");
  }
}

TEST_F(AesGcmBoringSslTest, BothMessageAndAadEmpty) {
  {  // Both are null string_view.
    const absl::string_view message;
    const absl::string_view aad;
    util::StatusOr<std::string> ciphertext = cipher_->Encrypt(message, aad);
    ASSERT_THAT(ciphertext.status(), IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, aad);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Both are empty string.
    const std::string message = "";
    const std::string aad = "";
    util::StatusOr<std::string> ciphertext = cipher_->Encrypt(message, aad);
    ASSERT_THAT(ciphertext.status(), IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, aad);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Both are default constructed string_view.
    util::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(absl::string_view(), absl::string_view());
    ASSERT_THAT(ciphertext.status(), IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, absl::string_view());
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, "");
  }
}

TEST_F(AesGcmBoringSslTest, InvalidKeySizes) {
  for (int keysize = 0; keysize < 65; keysize++) {
    util::SecretData key(keysize, 'x');
    util::StatusOr<std::unique_ptr<crypto::tink::Aead>> cipher =
        AesGcmBoringSsl::New(key);
    if (keysize == 16 || keysize == 32) {
      EXPECT_THAT(cipher.status(), IsOk());
    } else {
      EXPECT_THAT(cipher.status(), Not(IsOk()));
    }
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
    // AesGcmBoringSsl only supports 12-byte IVs and 16-byte authentication tag.
    // Also 24-byte keys are not supported.
    if (iv_size != 96 || tag_size != 128 || key_size == 192) {
      // Not supported
      continue;
    }
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string comment = test["comment"].GetString();
      util::SecretData key =
          util::SecretDataFromStringView(WycheproofUtil::GetBytes(test["key"]));
      std::string iv = WycheproofUtil::GetBytes(test["iv"]);
      std::string msg = WycheproofUtil::GetBytes(test["msg"]);
      std::string ct = WycheproofUtil::GetBytes(test["ct"]);
      std::string aad = WycheproofUtil::GetBytes(test["aad"]);
      std::string tag = WycheproofUtil::GetBytes(test["tag"]);
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string expected = test["result"].GetString();
      auto cipher = std::move(*AesGcmBoringSsl::New(key));
      auto result = cipher->Decrypt(iv + ct + tag, aad);
      bool success = result.ok();
      if (success) {
        std::string decrypted = *result;
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

TEST(AesGcmBoringSslTestWycheproofTest, TestVectors) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors("aes_gcm_test.json");
  ASSERT_TRUE(WycheproofTest(*root));
}

TEST(AesGcmBoringSslTestWycheproofTest, TestFipsOnly) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey128));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256));

  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key_128).status(), IsOk());
  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key_256).status(), IsOk());
}

TEST(AesGcmBoringSslTestWycheproofTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey128));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256));

  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key_128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key_256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
