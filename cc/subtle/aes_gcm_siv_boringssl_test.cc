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

#include "tink/subtle/aes_gcm_siv_boringssl.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ssl_util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr absl::string_view kKey256Hex =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAdditionalData = "Some data to authenticate.";

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;

TEST(AesGcmSivBoringSslTest, EncryptDecrypt) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256Hex));
  if (!internal::IsBoringSsl()) {
    EXPECT_THAT(AesGcmSivBoringSsl::New(key).status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  } else {
    util::StatusOr<std::unique_ptr<Aead>> aead = AesGcmSivBoringSsl::New(key);
    ASSERT_THAT(aead.status(), IsOk());

    util::StatusOr<std::string> ciphertext =
        (*aead)->Encrypt(kMessage, kAdditionalData);
    ASSERT_THAT(ciphertext.status(), IsOk());
    EXPECT_THAT(*ciphertext,
                SizeIs(kMessage.size() + kIvSizeInBytes + kTagSizeInBytes));
    util::StatusOr<std::string> plaintext =
        (*aead)->Decrypt(*ciphertext, kAdditionalData);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, kMessage);
  }
}

TEST(AesGcmSivBoringSslTest, DecryptFailsIfCiphertextTooSmall) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256Hex));
  util::StatusOr<std::unique_ptr<Aead>> aead = AesGcmSivBoringSsl::New(key);
  ASSERT_THAT(aead.status(), IsOk());

  for (int i = 1; i < kIvSizeInBytes + kTagSizeInBytes; i++) {
    std::string ciphertext;
    ResizeStringUninitialized(&ciphertext, i);
    EXPECT_THAT((*aead)->Decrypt(ciphertext, kAdditionalData).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(AesGcmSivBoringSslTest, TestFipsOnly) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(
          "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(AesGcmSivBoringSsl::New(key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(AesGcmSivBoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AesGcmSivBoringSslTestWycheproofTest, TestVectors) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  std::vector<internal::WycheproofTestVector> test_vectors =
      internal::ReadWycheproofTestVectors(
          /*file_name=*/"aes_gcm_siv_test.json");
  ASSERT_THAT(test_vectors, Not(IsEmpty()));

  for (const auto& test_vector : test_vectors) {
    if (test_vector.key.size() != 16 || test_vector.key.size() != 32 ||
        test_vector.nonce.size() != kIvSizeInBytes ||
        test_vector.tag.size() != 16) {
      continue;
    }

    util::SecretData key = util::SecretDataFromStringView(test_vector.key);
    util::StatusOr<std::unique_ptr<Aead>> cipher = AesGcmSivBoringSsl::New(key);
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

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
