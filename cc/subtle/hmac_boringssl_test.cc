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

#include "tink/subtle/hmac_boringssl.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "tink/config/tink_fips.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::StatusIs;

class HmacBoringSslTest : public ::testing::Test {
 public:
  // Utility to simplify testing with test vectors.
  // Arguments and result are hexadecimal.
  bool HmacVerifyHex(HashType hash, uint32_t tag_size,
                     const std::string &key_hex, const std::string &tag_hex,
                     const std::string &data_hex) {
    util::SecretData key =
        util::SecretDataFromStringView(absl::HexStringToBytes(key_hex));
    std::string tag = absl::HexStringToBytes(tag_hex);
    std::string data = absl::HexStringToBytes(data_hex);
    auto hmac_result = HmacBoringSsl::New(hash, tag_size, key);
    EXPECT_TRUE(hmac_result.ok()) << hmac_result.status();
    auto hmac = std::move(hmac_result.ValueOrDie());
    auto result = hmac->VerifyMac(tag, data);
    return result.ok();
  }
};

TEST_F(HmacBoringSslTest, testBasic) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f"));
  size_t tag_size = 16;
  auto hmac_result = HmacBoringSsl::New(HashType::SHA1, tag_size, key);
  EXPECT_TRUE(hmac_result.ok()) << hmac_result.status();
  auto hmac = std::move(hmac_result.ValueOrDie());
  { // Test with some example data.
    std::string data = "Some data to test.";
    auto res = hmac->ComputeMac(data);
    EXPECT_TRUE(res.ok()) << res.status().ToString();
    std::string tag = res.ValueOrDie();
    EXPECT_EQ(tag_size, tag.size());
    EXPECT_EQ(tag, absl::HexStringToBytes("9ccdca5b7fffb690df396e4ac49b9cd4"));
    auto status = hmac->VerifyMac(tag, data);
    EXPECT_TRUE(status.ok()) << "tag:" << absl::BytesToHexString(tag)
                             << " status:" << status.ToString();
  }
  { // Test with empty example data.
    absl::string_view data;
    auto res = hmac->ComputeMac(data);
    EXPECT_TRUE(res.ok()) << res.status().ToString();
    std::string tag = res.ValueOrDie();
    EXPECT_EQ(tag_size, tag.size());
    EXPECT_EQ(tag, absl::HexStringToBytes("5433122f77bcf8a4d9b874b4149823ef"));
    auto status = hmac->VerifyMac(tag, data);
    EXPECT_TRUE(status.ok()) << "tag:" << absl::BytesToHexString(tag)
                             << " status:" << status.ToString();
  }
}

TEST_F(HmacBoringSslTest, testModification) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f"));
  auto hmac_result = HmacBoringSsl::New(HashType::SHA1, 16, key);
  EXPECT_TRUE(hmac_result.ok()) << hmac_result.status();
  auto hmac = std::move(hmac_result.ValueOrDie());
  std::string data = "Some data to test";
  std::string tag = hmac->ComputeMac(data).ValueOrDie();
  auto status = hmac->VerifyMac(tag, data);
  EXPECT_TRUE(status.ok()) << status.ToString();
  size_t bits = tag.size() * 8;
  for (size_t i = 0; i < bits; i++) {
    std::string modified_tag = tag;
    modified_tag[i / 8] ^= 1 << (i % 8);
    EXPECT_FALSE(hmac->VerifyMac(modified_tag, data).ok())
        << "tag:" << absl::BytesToHexString(tag)
        << " modified:" << absl::BytesToHexString(modified_tag);
  }
}

TEST_F(HmacBoringSslTest, testTruncation) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key = util::SecretDataFromStringView(
      absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f"));
  auto hmac_result = HmacBoringSsl::New(HashType::SHA1, 20, key);
  EXPECT_TRUE(hmac_result.ok()) << hmac_result.status();
  auto hmac = std::move(hmac_result.ValueOrDie());
  std::string data = "Some data to test";
  std::string tag = hmac->ComputeMac(data).ValueOrDie();
  auto status = hmac->VerifyMac(tag, data);
  EXPECT_TRUE(status.ok()) << status.ToString();
  for (size_t i = 0; i < tag.size(); i++) {
    std::string modified_tag(tag, 0, i);
    EXPECT_FALSE(hmac->VerifyMac(modified_tag, data).ok())
        << "tag:" << absl::BytesToHexString(tag)
        << " modified:" << absl::BytesToHexString(modified_tag);
  }
}

TEST_F(HmacBoringSslTest, testInvalidKeySizes) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  size_t tag_size = 16;

  for (int keysize = 0; keysize < 65; keysize++) {
    util::SecretData key(keysize, 'x');
    auto hmac_result = HmacBoringSsl::New(HashType::SHA1, tag_size, key);
    if (keysize >= 16) {
      EXPECT_TRUE(hmac_result.ok());
    } else {
      EXPECT_FALSE(hmac_result.ok());
    }
  }
}

TEST_F(HmacBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::SecretData key128 = util::SecretDataFromStringView(
      absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f"));
  util::SecretData key256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(
          "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA1, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA224, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA256, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA384, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA512, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
}
// TODO(bleichen): Stuff to test
//  - Generate test vectors and share with Wycheproof.
//  - Tag size wrong for construction
//  - Tag size wrong during verification
//  - Generate invalid tags with 0s in the middle to catch comparison with
//    strcmp or similar.
//  - Generate invalid tags with equal diffs (e.g. to catch broken constant
//    time comparisons.
//  - wrong size of tag during verification
//  - Hmac key size must not be 0 (see RFC)
//  - Generate test vectors with key sizes larger than the block size of the
//    hash. (HMAC hashes these keys).

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

