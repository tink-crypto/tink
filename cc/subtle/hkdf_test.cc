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

#include "tink/subtle/hkdf.h"

#include "gtest/gtest.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class HkdfTest : public ::testing::Test {};

struct TestVector {
  HashType hash_type;
  std::string ikm_hex;
  std::string salt_hex;
  std::string info_hex;
  size_t out_len;
  std::string out_key_hex;
};

// Tests vectors from RFC 5869.
static const std::vector<TestVector> test_vector(
    {{
         HashType::SHA256, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
         "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007"
         "208"
         "d5b887185865",
     },
     {
         HashType::SHA256,
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
         "404142434445464748494a4b4c4d4e4f",
         "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
         "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
         "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
         "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
         "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
         "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
         82,
         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
         "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
         "cc30c58179ec3e87c14c01d5c1f3434f1d87",
     },
     {HashType::SHA256, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
      42,
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
      "9d201395faa4b61a96c8"},
     {HashType::SHA1, "0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c",
      "f0f1f2f3f4f5f6f7f8f9", 42,
      "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e4224"
      "78d305f3f896"},
     {HashType::SHA1,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
      "404142434445464748494a4b4c4d4e4f",
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      82,
      "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe"
      "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e"
      "927336d0441f4c4300e2cff0d0900b52d3b4"},
     {HashType::SHA1, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
      42,
      "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0"
      "ea00033de03984d34918"}});

TEST_F(HkdfTest, testBasic) {
  for (const TestVector& test : test_vector) {
    auto hkdf_or =
        Hkdf::ComputeHkdf(test.hash_type, test::HexDecodeOrDie(test.ikm_hex),
                          test::HexDecodeOrDie(test.salt_hex),
                          test::HexDecodeOrDie(test.info_hex), test.out_len);
    ASSERT_TRUE(hkdf_or.ok());
    EXPECT_EQ(test::HexEncode(hkdf_or.ValueOrDie()), test.out_key_hex);
  }
}

TEST_F(HkdfTest, testBasicSecretData) {
  for (const TestVector& test : test_vector) {
    auto hkdf_or = Hkdf::ComputeHkdf(
        test.hash_type,
        util::SecretDataFromStringView(test::HexDecodeOrDie(test.ikm_hex)),
        test::HexDecodeOrDie(test.salt_hex),
        test::HexDecodeOrDie(test.info_hex), test.out_len);
    ASSERT_TRUE(hkdf_or.ok());
    EXPECT_EQ(
        test::HexEncode(util::SecretDataAsStringView(hkdf_or.ValueOrDie())),
        test.out_key_hex);
  }
}

TEST_F(HkdfTest, testLongOutput) {
  TestVector test = test_vector[0];
  auto status_or_string = Hkdf::ComputeHkdf(
      test.hash_type, test::HexDecodeOrDie(test.ikm_hex),
      test::HexDecodeOrDie(test.salt_hex), test::HexDecodeOrDie(test.info_hex),
      255 * 32 + 1 /* 255 * hashLength + 1 */);
  EXPECT_FALSE(status_or_string.ok());
  EXPECT_EQ(status_or_string.status().message(), "BoringSSL's HKDF failed");
}

TEST_F(HkdfTest, ComputeEciesHkdfSecretData) {
  for (const TestVector& test : test_vector) {
    std::string ikm = test::HexDecodeOrDie(test.ikm_hex);
    std::string kem_bytes = ikm.substr(0, ikm.size() / 2);
    util::SecretData shared_secret(ikm.begin() + ikm.size() / 2, ikm.end());
    auto hkdf_or = Hkdf::ComputeEciesHkdfSymmetricKey(
        test.hash_type, kem_bytes, shared_secret,
        test::HexDecodeOrDie(test.salt_hex),
        test::HexDecodeOrDie(test.info_hex), test.out_len);
    ASSERT_TRUE(hkdf_or.ok());
    EXPECT_EQ(
        test::HexEncode(util::SecretDataAsStringView(hkdf_or.ValueOrDie())),
        test.out_key_hex);
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

