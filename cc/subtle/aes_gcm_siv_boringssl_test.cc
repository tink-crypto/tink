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

#include "gtest/gtest.h"
#include "absl/status/status.h"
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

using ::crypto::tink::test::StatusIs;

TEST(AesGcmSivBoringSslTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = AesGcmSivBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  auto ct = cipher->Encrypt(message, aad);
  EXPECT_TRUE(ct.ok()) << ct.status();
  // The ciphertext is the concatenation of the nonce, the encrypted message
  // and the tag.
  const int TAG_SIZE = 16;
  const int NONCE_SIZE = 12;
  EXPECT_EQ(ct.ValueOrDie().size(), NONCE_SIZE + message.size() + TAG_SIZE);
  auto pt = cipher->Decrypt(ct.ValueOrDie(), aad);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(AesGcmSivBoringSslTest, Sizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto res = AesGcmSivBoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  // message size
  std::string message;
  std::string aad;
  for (size_t size = 0; size < 1100; size++) {
    message += static_cast<const char>(size % 101);
    auto ct = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct.ok()) << ct.status();
    auto pt = cipher->Decrypt(ct.ValueOrDie(), aad);
    EXPECT_TRUE(pt.ok()) << pt.status();
    EXPECT_EQ(pt.ValueOrDie(), message);
  }
  // aad sizes
  message = "";
  for (size_t size = 0; size < 1100; size++) {
    aad += static_cast<const char>(size % 101);
    auto ct = cipher->Encrypt(message, aad);
    EXPECT_TRUE(ct.ok()) << ct.status();
    auto pt = cipher->Decrypt(ct.ValueOrDie(), aad);
    EXPECT_TRUE(pt.ok()) << pt.status();
    EXPECT_EQ(pt.ValueOrDie(), message);
  }
}

TEST(AesGcmSivBoringSslTest, Modification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmSivBoringSsl::New(key).ValueOrDie());
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
  // ... and a final check that no modification corrupted the internal state.
  EXPECT_TRUE(cipher->Decrypt(ct, aad).ok());
}

TEST(AesGcmSivBoringSslTest, AadEmptyVersusNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmSivBoringSsl::New(key).ValueOrDie());
  const std::string message = "Some data to encrypt.";
  // Encryption
  // AAD is a null string_view.
  const absl::string_view aad;
  auto ct0_or_status = cipher->Encrypt(message, aad);
  EXPECT_TRUE(ct0_or_status.ok()) << ct0_or_status.status();
  auto ct0 = ct0_or_status.ValueOrDie();
  // AAD is a an empty string.
  auto ct1_or_status = cipher->Encrypt(message, "");
  EXPECT_TRUE(ct1_or_status.ok()) << ct1_or_status.status();
  auto ct1 = ct1_or_status.ValueOrDie();
  // AAD is a default constructed string_view.
  auto ct2_or_status = cipher->Encrypt(message, absl::string_view());
  EXPECT_TRUE(ct2_or_status.ok()) << ct2_or_status.status();
  auto ct2 = ct2_or_status.ValueOrDie();

  // Decrypts all ciphertexts the different versions of AAD.
  // AAD is a null string_view.
  auto pt = cipher->Decrypt(ct0, aad);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
  pt = cipher->Decrypt(ct1, aad);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
  pt = cipher->Decrypt(ct2, aad);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());

  // AAD is a an empty string.
  pt = cipher->Decrypt(ct0, "");
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
  pt = cipher->Decrypt(ct1, "");
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
  pt = cipher->Decrypt(ct2, "");
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());

  // AAD is a default constructed string_view.
  pt = cipher->Decrypt(ct0, absl::string_view());
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
  pt = cipher->Decrypt(ct1, absl::string_view());
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
  pt = cipher->Decrypt(ct2, absl::string_view());
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(message, pt.ValueOrDie());
}

TEST(AesGcmSivBoringSslTest, MessageEmptyVersusNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesGcmSivBoringSsl::New(key).ValueOrDie());
  const std::string aad = "Some data to authenticate.";
  const std::string nonce = test::HexDecodeOrDie("00112233445566778899aabb");
  // Message is a null string_view.
  const absl::string_view message0;
  auto ct0_or_status = cipher->Encrypt(message0, aad);
  EXPECT_TRUE(ct0_or_status.ok());
  auto ct0 = ct0_or_status.ValueOrDie();
  auto pt0_or_status = cipher->Decrypt(ct0, aad);
  EXPECT_TRUE(pt0_or_status.ok()) << pt0_or_status.status();
  auto pt0 = pt0_or_status.ValueOrDie();
  EXPECT_EQ("", pt0);

  // Message is an empty string.
  const std::string message1 = "";
  auto ct1_or_status = cipher->Encrypt(message1, aad);
  EXPECT_TRUE(ct1_or_status.ok());
  auto ct1 = ct1_or_status.ValueOrDie();
  auto pt1_or_status = cipher->Decrypt(ct1, aad);
  EXPECT_TRUE(pt1_or_status.ok()) << pt1_or_status.status();
  auto pt1 = pt1_or_status.ValueOrDie();
  EXPECT_EQ("", pt1);

  // Message is a default constructed string_view.
  auto ct2_or_status = cipher->Encrypt(absl::string_view(), aad);
  EXPECT_TRUE(ct2_or_status.ok());
  auto ct2 = ct2_or_status.ValueOrDie();
  auto pt2_or_status = cipher->Decrypt(ct2, aad);
  EXPECT_TRUE(pt2_or_status.ok()) << pt2_or_status.status();
  auto pt2 = pt2_or_status.ValueOrDie();
  EXPECT_EQ("", pt2);
}

TEST(AesGcmSivBoringSslTest, InvalidKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    if (keysize == 16 || keysize == 32) {
      continue;
    }
    util::SecretData key(keysize, 'x');
    auto cipher = AesGcmSivBoringSsl::New(key);
    EXPECT_FALSE(cipher.ok());
  }
}

// Test with test vectors from Wycheproof project.
bool WycheproofTest(const rapidjson::Document& root) {
  int errors = 0;
  for (const rapidjson::Value& test_group : root["testGroups"].GetArray()) {
    const size_t iv_size = test_group["ivSize"].GetInt();
    const size_t key_size = test_group["keySize"].GetInt();
    const size_t tag_size = test_group["tagSize"].GetInt();
    // AesGcmSivBoringSsl only supports 12-byte IVs and 16-byte authentication
    // tag. Key sizes are either 128 bits or 256 bits. tink supports both.
    // Invalid test vectors may contain other sizes.
    if (key_size != 128 && key_size != 256) {
      continue;
    }
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string comment = test["comment"].GetString();
      util::SecretData key =
          util::SecretDataFromStringView(WycheproofUtil::GetBytes(test["key"]));
      std::string nonce = WycheproofUtil::GetBytes(test["iv"]);
      std::string msg = WycheproofUtil::GetBytes(test["msg"]);
      std::string ct = WycheproofUtil::GetBytes(test["ct"]);
      std::string aad = WycheproofUtil::GetBytes(test["aad"]);
      std::string tag = WycheproofUtil::GetBytes(test["tag"]);
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string expected = test["result"].GetString();
      auto cipher = std::move(AesGcmSivBoringSsl::New(key).ValueOrDie());

      // Tests decryption only, since the AEAD interface does
      // not allow to set the nonce.
      auto dec = cipher->Decrypt(nonce + ct + tag, aad);
      if (dec.ok()) {
        std::string decrypted = dec.ValueOrDie();
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
                        << " key_size:" << key_size
                        << " error:" << dec.status();
          errors++;
        }
      }
    }
  }
  return errors == 0;
}

TEST(AesGcmSivBoringSslTest, TestVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors("aes_gcm_siv_test.json");
  ASSERT_TRUE(WycheproofTest(*root));
}

TEST(AesGcmSivBoringSslTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesGcmSivBoringSsl::New(key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesGcmSivBoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
