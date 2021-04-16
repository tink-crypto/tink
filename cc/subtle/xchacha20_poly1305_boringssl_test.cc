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

#include "tink/subtle/xchacha20_poly1305_boringssl.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "openssl/err.h"
#include "tink/config/tink_fips.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::StatusIs;

TEST(XChacha20Poly1305BoringSslTest, TestBasic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));
  auto res = XChacha20Poly1305BoringSsl::New(key);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  auto ct = cipher->Encrypt(message, aad);
  EXPECT_TRUE(ct.ok()) << ct.status();
  EXPECT_EQ(ct.ValueOrDie().size(),
            message.size() + 24 /* nonce */ + 16 /* tag */);
  auto pt = cipher->Decrypt(ct.ValueOrDie(), aad);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(XChacha20Poly1305BoringSslTest, TestModification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(XChacha20Poly1305BoringSsl::New(key).ValueOrDie());
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
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
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
  {  // AAD is a default-constructed string_view.
    auto pt_or_status = cipher->Decrypt(ct, absl::string_view());
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ(message, pt);
  }
}

TEST(XChacha20Poly1305BoringSslTest, TestAadEmptyVersusNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const util::SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(
          "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(XChacha20Poly1305BoringSsl::New(key).ValueOrDie());
  {  // AAD is a null string_view.
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
  {  // AAD is a default-constructed string_view.
    const std::string message = "Some data to encrypt.";
    auto ct_or_status = cipher->Encrypt(message, absl::string_view());
    EXPECT_TRUE(ct_or_status.ok()) << ct_or_status.status();
    auto ct = ct_or_status.ValueOrDie();
    TestDecryptWithEmptyAad(cipher.get(), ct, message);
  }
}

TEST(XChacha20Poly1305BoringSslTest, TestMessageEmptyVersusNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const util::SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(
          "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(XChacha20Poly1305BoringSsl::New(key).ValueOrDie());
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
  {  // Message is a default-constructed string_view.
    auto ct_or_status = cipher->Encrypt(absl::string_view(), aad);
    EXPECT_TRUE(ct_or_status.ok());
    auto ct = ct_or_status.ValueOrDie();
    auto pt_or_status = cipher->Decrypt(ct, aad);
    EXPECT_TRUE(pt_or_status.ok()) << pt_or_status.status();
    auto pt = pt_or_status.ValueOrDie();
    EXPECT_EQ("", pt);
  }
}

TEST(XChacha20Poly1305BoringSslTest, TestBothMessageAndAadEmpty) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const util::SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(
          "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(XChacha20Poly1305BoringSsl::New(key).ValueOrDie());
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
  {  // Both are default-constructed string_view.
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

TEST(XChacha20Poly1305BoringSslTest, TestInvalidKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    if (keysize == 32) {
      continue;
    }
    util::SecretData key(keysize, 'x');
    auto cipher = XChacha20Poly1305BoringSsl::New(key);
    EXPECT_FALSE(cipher.ok());
  }
}

TEST(XChacha20Poly1305BoringSslTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  util::SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  auto xchacha20_poly1305_res = subtle::XChacha20Poly1305BoringSsl::New(key256);
  EXPECT_THAT(xchacha20_poly1305_res.status(), StatusIs(util::error::INTERNAL));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
