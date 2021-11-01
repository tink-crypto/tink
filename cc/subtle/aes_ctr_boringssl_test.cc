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

#include "tink/subtle/aes_ctr_boringssl.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/random.h"
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

TEST(AesCtrBoringSslTest, TestEncryptDecrypt) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  int iv_size = 12;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  auto ct = cipher->Encrypt(message);
  EXPECT_TRUE(ct.ok()) << ct.status();
  EXPECT_EQ(ct.ValueOrDie().size(), message.size() + iv_size);
  auto pt = cipher->Decrypt(ct.ValueOrDie());
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(AesCtrBoringSslTest, TestEncryptDecrypt_randomMessage) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  int iv_size = 12;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  for (int i = 0; i < 256; i++) {
    std::string message = Random::GetRandomBytes(i);
    auto ct = cipher->Encrypt(message);
    EXPECT_TRUE(ct.ok()) << ct.status();
    EXPECT_EQ(ct.ValueOrDie().size(), message.size() + iv_size);
    auto pt = cipher->Decrypt(ct.ValueOrDie());
    EXPECT_TRUE(pt.ok()) << pt.status();
    EXPECT_EQ(pt.ValueOrDie(), message);
  }
}

TEST(AesCtrBoringSslTest, TestEncryptDecrypt_randomKey_randomMessage) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  for (int i = 0; i < 256; i++) {
    util::SecretData key = Random::GetRandomKeyBytes(16);
    int iv_size = 12;
    auto res = AesCtrBoringSsl::New(key, iv_size);
    EXPECT_TRUE(res.ok()) << res.status();
    auto cipher = std::move(res.ValueOrDie());
    std::string message = Random::GetRandomBytes(i);
    auto ct = cipher->Encrypt(message);
    EXPECT_TRUE(ct.ok()) << ct.status();
    EXPECT_EQ(ct.ValueOrDie().size(), message.size() + iv_size);
    auto pt = cipher->Decrypt(ct.ValueOrDie());
    EXPECT_TRUE(pt.ok()) << pt.status();
    EXPECT_EQ(pt.ValueOrDie(), message);
  }
}

TEST(AesCtrBoringSslTest, TestEncryptDecrypt_invalidIvSize) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  int iv_size = 11;
  auto res1 = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_FALSE(res1.ok()) << res1.status();

  iv_size = 17;
  auto res2 = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_FALSE(res2.ok()) << res2.status();
}

TEST(AesCtrBoringSslTest, TestNistTestVector) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  // NIST SP 800-38A pp 55.
  util::SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("2b7e151628aed2a6abf7158809cf4f3c"));
  std::string ciphertext(test::HexDecodeOrDie(
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff874d6191b620e3261bef6864990db6ce"));
  std::string message(test::HexDecodeOrDie("6bc1bee22e409f96e93d7e117393172a"));
  int iv_size = 16;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  auto pt = cipher->Decrypt(ciphertext);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(AesCtrBoringSslTest, TestMultipleEncrypt) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = Random::GetRandomKeyBytes(16);
  int iv_size = 12;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  auto ct1 = cipher->Encrypt(message);
  auto ct2 = cipher->Encrypt(message);
  EXPECT_NE(ct1.ValueOrDie(), ct2.ValueOrDie());
}

TEST(AesCtrBoringSslTest, TestFipsOnly) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesCtrBoringSsl::New(key128, 16).status(), IsOk());
  EXPECT_THAT(subtle::AesCtrBoringSsl::New(key256, 16).status(), IsOk());
}

TEST(AesCtrBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesCtrBoringSsl::New(key128, 16).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesCtrBoringSsl::New(key256, 16).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
