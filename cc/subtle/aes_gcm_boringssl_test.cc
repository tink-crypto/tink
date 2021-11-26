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
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/config/tink_fips.h"
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
using ::testing::AllOf;
using ::testing::Eq;
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
  util::StatusOr<std::string> ciphertext = cipher_->Encrypt(kMessage, kAad);
  ASSERT_THAT(ciphertext.status(), IsOk());
  ASSERT_THAT(cipher_->Decrypt(*ciphertext, kAad).status(), IsOk());
  // Modify the ciphertext.
  for (size_t i = 0; i < ciphertext->size() * 8; i++) {
    std::string modified_ct = *ciphertext;
    modified_ct[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT(cipher_->Decrypt(modified_ct, kAad).status(), Not(IsOk())) << i;
  }
  // Modify the additional data.
  for (size_t i = 0; i < kAad.size() * 8; i++) {
    std::string modified_aad = std::string(kAad);
    modified_aad[i / 8] ^= 1 << (i % 8);
    auto decrypted = cipher_->Decrypt(*ciphertext, modified_aad);
    EXPECT_THAT(decrypted.status(), Not(IsOk())) << i << " pt:" << *decrypted;
  }
  // Truncate the ciphertext.
  for (size_t i = 0; i < ciphertext->size(); i++) {
    std::string truncated_ct(*ciphertext, 0, i);
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

TEST(AesGcmBoringSslWycheproofTest, TestVectors) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }
  std::vector<internal::WycheproofTestVector> test_vectors =
      internal::ReadWycheproofTestVectors(
          /*file_name=*/"aes_gcm_test.json",
          /*allowed_tag_size_in_bytes=*/16, /*allowed_iv_size_in_bytes=*/12,
          /*allowed_key_sizes_in_bytes*/ {16, 32});
  for (const auto& test_vector : test_vectors) {
    util::SecretData key = util::SecretDataFromStringView(test_vector.key);
    util::StatusOr<std::unique_ptr<Aead>> cipher = AesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher.status(), IsOk());
    std::string ciphertext =
        absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);
    util::StatusOr<std::string> plaintext =
        (*cipher)->Decrypt(ciphertext, test_vector.aad);
    if (plaintext.ok()) {
      EXPECT_NE(test_vector.expected, "invalid")
          << "Decrypted invalid ciphertext with ID " << test_vector.id;
      EXPECT_EQ(*plaintext, test_vector.msg)
          << "Incorrect decryption: " << test_vector.id;
    } else {
      EXPECT_THAT(test_vector.expected,
                  Not(AllOf(Eq("valid"), Eq("acceptable"))))
          << "Could not decrypt test with tcId: " << test_vector.id
          << " iv_size: " << test_vector.nonce.size()
          << " tag_size: " << test_vector.tag.size()
          << " key_size: " << key.size() << "; error: " << plaintext.status();
    }
  }
}

TEST(AesGcmBoringSslFipsTest, FipsOnly) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey128));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256));

  EXPECT_THAT(AesGcmBoringSsl::New(key_128).status(), IsOk());
  EXPECT_THAT(AesGcmBoringSsl::New(key_256).status(), IsOk());
}

TEST(AesGcmBoringSslFipsTest, FipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey128));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256));

  EXPECT_THAT(AesGcmBoringSsl::New(key_128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(AesGcmBoringSsl::New(key_256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
