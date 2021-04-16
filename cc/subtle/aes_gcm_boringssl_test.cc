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
#include "absl/strings/str_cat.h"
#include "openssl/err.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

TEST(AesGcmBoringSslTest, testBasic) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = AesGcmBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  auto ct = cipher->Encrypt(message, aad);
  EXPECT_TRUE(ct.ok()) << ct.status();
  EXPECT_EQ(ct.ValueOrDie().size(), message.size() + 12 + 16);
  auto pt = cipher->Decrypt(ct.ValueOrDie(), aad);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(AesGcmBoringSslTest, testModification) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmBoringSsl::New(key).ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  std::string ct = cipher->Encrypt(message, aad).ValueOrDie();
  EXPECT_TRUE(cipher->Decrypt(ct, aad).ok());
  // Modify the ciphertext
  for (size_t i = 0; i < ct.size() * 8; i++) {
    std::string modified_ct = ct;
    modified_ct[i / 8] ^= 1 << (i % 8);
    EXPECT_FALSE(cipher->Decrypt(modified_ct, aad).ok()) << i;
  }
  // Modify the additional data
  for (size_t i = 0; i < aad.size() * 8; i++) {
    std::string modified_aad = aad;
    modified_aad[i / 8] ^= 1 << (i % 8);
    auto decrypted = cipher->Decrypt(ct, modified_aad);
    EXPECT_FALSE(decrypted.ok()) << i << " pt:" << decrypted.ValueOrDie();
  }
  // Truncate the ciphertext
  for (size_t i = 0; i < ct.size(); i++) {
    std::string truncated_ct(ct, 0, i);
    EXPECT_FALSE(cipher->Decrypt(truncated_ct, aad).ok()) << i;
  }
}

void TestDecryptWithEmptyAad(crypto::tink::Aead* cipher, absl::string_view ct,
                             absl::string_view message) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  {  // AAD is a null string_view.
    const absl::string_view aad;
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ(message, pt);
  }
  {  // AAD is a an empty string.
    auto pt_or_status = cipher->Decrypt(ct, "");
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ(message, pt);
  }
  {  // AAD is a default constructed string_view.
    auto pt_or_status = cipher->Decrypt(ct, absl::string_view());
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ(message, pt);
  }
}

TEST(AesGcmBoringSslTest, testAadEmptyVersusNullStringView) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  const util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmBoringSsl::New(key).ValueOrDie());
  { // AAD is a null string_view.
    const std::string message = "Some data to encrypt.";
    const absl::string_view aad;
    auto ct_or_status = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct_or_status.ok()) << ct_or_status.status();
    auto ct = ct_or_status.ValueOrDie();
    TestDecryptWithEmptyAad(cipher.get(), ct, message);
  }
  {  // AAD is a an empty string.
    const std::string message = "Some data to encrypt.";
    auto ct_or_status = cipher->Encrypt(message, "");
    EXPECT_TRUE(ct_or_status.ok()) << ct_or_status.status();
    auto ct = ct_or_status.ValueOrDie();
    TestDecryptWithEmptyAad(cipher.get(), ct, message);
  }
  {  // AAD is a default constructed string_view.
    const std::string message = "Some data to encrypt.";
    auto ct_or_status = cipher->Encrypt(message, absl::string_view());
    EXPECT_TRUE(ct_or_status.ok()) << ct_or_status.status();
    auto ct = ct_or_status.ValueOrDie();
    TestDecryptWithEmptyAad(cipher.get(), ct, message);
  }
}

TEST(AesGcmBoringSslTest, testMessageEmptyVersusNullStringView) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  const util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmBoringSsl::New(key).ValueOrDie());
  const std::string aad = "Some data to authenticate.";
  {  // Message is a null string_view.
    const absl::string_view message;
    auto ct_or_status = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
  {  // Message is an empty string.
    const std::string message = "";
    auto ct_or_status = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
  {  // Message is a default constructed string_view.
    auto ct_or_status = cipher->Encrypt(absl::string_view(), aad);
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
}

TEST(AesGcmBoringSslTest, testBothMessageAndAadEmpty) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  const util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmBoringSsl::New(key).ValueOrDie());
  {  // Both are null string_view.
    const absl::string_view message;
    const absl::string_view aad;
    auto ct_or_status = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
  {  // Both are empty string.
    const std::string message = "";
    const std::string aad = "";
    auto ct_or_status = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
  {  // Both are default constructed string_view.
    auto ct_or_status =
        cipher->Encrypt(absl::string_view(), absl::string_view());
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, absl::string_view());
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
}

TEST(AesGcmBoringSslTest, testInvalidKeySizes) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    util::SecretData key(keysize, 'x');
    auto cipher = AesGcmBoringSsl::New(key);
    EXPECT_THAT(cipher.ok(), Eq(keysize == 16 || keysize == 32));
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
bool WycheproofTest(const rapidjson::Document &root) {
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
      auto cipher =
         std::move(AesGcmBoringSsl::New(key).ValueOrDie());
      auto result = cipher->Decrypt(iv + ct + tag, aad);
      bool success = result.ok();
      if (success) {
        std::string decrypted = result.ValueOrDie();
        if (expected == "invalid") {
          ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
          errors++;
        } else if (msg != decrypted) {
          ADD_FAILURE() << "Incorrect decryption:" << id;
          errors++;
        }
      } else {
        if (expected == "valid" || expected == "acceptable") {
          ADD_FAILURE()
              << "Could not decrypt test with tcId:" << id
              << " iv_size:" << iv_size
              << " tag_size:" << tag_size
              << " key_size:" << key_size
              << " error:" << GetError();
          errors++;
        }
      }
    }
  }
  return errors == 0;
}

TEST(AesGcmBoringSslTest, TestVectors) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors("aes_gcm_test.json");
  ASSERT_TRUE(WycheproofTest(*root));
}

TEST(AesGcmBoringSslTest, TestFipsOnly) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key128).status(), IsOk());
  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key256).status(), IsOk());
}

TEST(AesGcmBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key128).status(),
              StatusIs(util::error::INTERNAL));
  EXPECT_THAT(subtle::AesGcmBoringSsl::New(key256).status(),
              StatusIs(util::error::INTERNAL));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
