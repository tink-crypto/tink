// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/stateful_hmac_boringssl.h"

#include <cstddef>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/subtle/common_enums.h"
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

constexpr size_t kTagSize = 16;
constexpr size_t kSmallTagSize = 10;

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;
using ::testing::StrEq;

void EmptyHmac(HashType hash_type, uint32_t tag_size, std::string key,
               std::string expected) {
  auto hmac_result = StatefulHmacBoringSsl::New(
      hash_type, tag_size, util::SecretDataFromStringView(key));
  EXPECT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  auto result = hmac->Finalize();
  EXPECT_THAT(result, IsOk());

  auto tag = result.value();
  EXPECT_EQ(tag.size(), tag_size);
  EXPECT_EQ(tag, expected);
}

TEST(StatefulHmacBoringSslTest, testEmpty) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));

  std::string expected_256(
      test::HexDecodeOrDie("07eff8b326b7798c9ccfcbdbe579489a"));
  EmptyHmac(HashType::SHA256, kTagSize, key, expected_256);

  std::string expected_512(
      test::HexDecodeOrDie("2fec800ca276c44985a35aec92067e5e"));
  EmptyHmac(HashType::SHA512, kTagSize, key, expected_512);

  std::string expected_256_small(test::HexDecodeOrDie("07eff8b326b7798c9ccf"));
  EmptyHmac(HashType::SHA256, kSmallTagSize, key, expected_256_small);

  std::string expected_512_small(test::HexDecodeOrDie("2fec800ca276c44985a3"));
  EmptyHmac(HashType::SHA512, kSmallTagSize, key, expected_512_small);
}

void BasicHmac(HashType hash_type, uint32_t tag_size, std::string key,
               std::string data, std::string expected) {
  auto hmac_result = StatefulHmacBoringSsl::New(
      hash_type, tag_size, util::SecretDataFromStringView(key));
  EXPECT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());

  auto update_result = hmac->Update(data);
  EXPECT_THAT(update_result, IsOk());
  auto result = hmac->Finalize();
  EXPECT_THAT(result, IsOk());

  auto tag = result.value();
  EXPECT_EQ(tag.size(), tag_size);
  EXPECT_EQ(tag, expected);
}

TEST(StatefulHmacBoringSslTest, testBasic) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  std::string data = "Some data to test.";

  std::string expected_256(
      test::HexDecodeOrDie("1d6eb74bc283f7947e92c72bd985ce6e"));
  BasicHmac(HashType::SHA256, kTagSize, key, data, expected_256);

  std::string expected_512(
      test::HexDecodeOrDie("72b8ff800f57f9aeec41265a29b69b6a"));
  BasicHmac(HashType::SHA512, kTagSize, key, data, expected_512);

  std::string expected_256_small(test::HexDecodeOrDie("1d6eb74bc283f7947e92"));
  BasicHmac(HashType::SHA256, kSmallTagSize, key, data, expected_256_small);

  std::string expected_512_small(test::HexDecodeOrDie("72b8ff800f57f9aeec41"));
  BasicHmac(HashType::SHA512, kSmallTagSize, key, data, expected_512_small);
}

void MultipleUpdateHmac(HashType hash_type, uint32_t tag_size, std::string key,
                        std::string data1, std::string data2, std::string data3,
                        std::string data4, std::string expected) {
  auto hmac_result = StatefulHmacBoringSsl::New(
      hash_type, tag_size, util::SecretDataFromStringView(key));
  EXPECT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());

  auto update_1 = hmac->Update(data1);
  EXPECT_THAT(update_1, IsOk());
  auto update_2 = hmac->Update(data2);
  EXPECT_THAT(update_2, IsOk());
  auto update_3 = hmac->Update(data3);
  EXPECT_THAT(update_3, IsOk());
  auto update_4 = hmac->Update(data4);
  EXPECT_THAT(update_4, IsOk());

  auto result = hmac->Finalize();
  EXPECT_THAT(result, IsOk());

  auto tag = result.value();
  EXPECT_EQ(tag.size(), tag_size);
  EXPECT_EQ(tag, expected);
}

TEST(StatefulHmacBoringSslTest, testMultipleUpdates) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  std::string data1 = "Some ", data2 = "data ", data3 = "to ", data4 = "test.";

  // The tags are the same as the tags in testBasic, since they have the same
  // key and the same input, but testMultipleUpdates uses multiple updates.

  std::string expected_256(
      test::HexDecodeOrDie("1d6eb74bc283f7947e92c72bd985ce6e"));
  MultipleUpdateHmac(HashType::SHA256, kTagSize, key, data1, data2, data3,
                     data4, expected_256);

  std::string expected_512(
      test::HexDecodeOrDie("72b8ff800f57f9aeec41265a29b69b6a"));
  MultipleUpdateHmac(HashType::SHA512, kTagSize, key, data1, data2, data3,
                     data4, expected_512);

  std::string expected_256_small(test::HexDecodeOrDie("1d6eb74bc283f7947e92"));
  MultipleUpdateHmac(HashType::SHA256, kSmallTagSize, key, data1, data2, data3,
                     data4, expected_256_small);

  std::string expected_512_small(test::HexDecodeOrDie("72b8ff800f57f9aeec41"));
  MultipleUpdateHmac(HashType::SHA512, kSmallTagSize, key, data1, data2, data3,
                     data4, expected_512_small);
}

TEST(StatefulHmacBoringSslTest, testInvalidKeySizes) {
  size_t tag_size = 16;

  for (int keysize = 0; keysize < 65; keysize++) {
    std::string key(keysize, 'x');
    auto hmac_result = StatefulHmacBoringSsl::New(
        HashType::SHA256, tag_size, util::SecretDataFromStringView(key));
    if (keysize >= 16) {
      EXPECT_THAT(hmac_result, IsOk());
    } else {
      EXPECT_THAT(hmac_result.status(),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("invalid key size")));
    }
  }
}

TEST(StatefulCmacFactoryTest, createsObjects) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  std::string data = "Some data to test.";

  std::string expected(
      test::HexDecodeOrDie("1d6eb74bc283f7947e92c72bd985ce6e"));
  BasicHmac(HashType::SHA256, kTagSize, key, data, expected);
  auto factory = absl::make_unique<StatefulHmacBoringSslFactory>(
      HashType::SHA256, kTagSize, util::SecretDataFromStringView(key));
  auto stateful_hmac_or = factory->Create();
  ASSERT_THAT(stateful_hmac_or, IsOk());
  auto stateful_hmac = std::move(stateful_hmac_or.value());
  EXPECT_THAT(stateful_hmac->Update(data), IsOk());
  auto output_or = stateful_hmac->Finalize();
  ASSERT_THAT(output_or, IsOk());
  auto output = output_or.value();
  EXPECT_THAT(output, StrEq(expected));
}

class StatefulHmacBoringSslTestVectorTest
    : public ::testing::TestWithParam<std::pair<int, std::string>> {
 public:
  // Utility to simplify testing with test vectors.
  // Arguments and result are hexadecimal.
  void StatefulHmacVerifyHex(const std::string &key_hex,
                             const std::string &msg_hex,
                             const std::string &tag_hex) {
    std::string key = test::HexDecodeOrDie(key_hex);
    std::string tag = test::HexDecodeOrDie(tag_hex);
    std::string msg = test::HexDecodeOrDie(msg_hex);
    auto create_result = StatefulHmacBoringSsl::New(
        HashType::SHA1, tag.size(), util::SecretDataFromStringView(key));
    EXPECT_THAT(create_result, IsOk());
    auto hmac = std::move(create_result.value());

    auto update_result = hmac->Update(msg);
    EXPECT_THAT(update_result, IsOk());

    auto finalize_result = hmac->Finalize();
    EXPECT_THAT(finalize_result, IsOk());
    auto result = finalize_result.value();

    EXPECT_EQ(result, tag);
  }
};

// Wycheproof HMAC tests are not enabled because the test vectors are in
// "rc" (release candidate) state, and are not yet exported for use.
// TODO(cathieyun): re-enable Wycheproof HMAC tests once vectors are exported.

/*
// Test with test vectors from Wycheproof project.
bool WycheproofTest(const rapidjson::Document &root, HashType hash_type) {
  int errors = 0;
  for (const rapidjson::Value &test_group : root["testGroups"].GetArray()) {
    // Get the key size in bytes. Wycheproof contains tests for keys smaller
    // than MIN_KEY_SIZE, which is 16, so the test will skip those.
    if (test_group["keySize"].GetInt() / 8 < 16) {
      continue;
    }
    for (const rapidjson::Value &test : test_group["tests"].GetArray()) {
      std::string comment = test["comment"].GetString();
      std::string key = WycheproofUtil::GetBytes(test["key"]);
      std::string msg = WycheproofUtil::GetBytes(test["msg"]);
      std::string tag = WycheproofUtil::GetBytes(test["tag"]);
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string expected = test["result"].GetString();

      auto create_result =
          StatefulHmacBoringSsl::New(hash_type, tag.length(), key);
      EXPECT_THAT(create_result, IsOk());
      auto hmac = std::move(create_result.value());

      auto update_result = hmac->Update(msg);
      EXPECT_THAT(update_result, IsOk());

      auto finalize_result = hmac->Finalize();
      auto result = finalize_result.value();

      bool success = result == tag;
      if (success) {
        // std::string result_tag = result.value();
        if (expected == "invalid") {
          ADD_FAILURE() << "verified incorrect tag:" << id;
          errors++;
        }
      } else {
        if (expected == "valid") {
          ADD_FAILURE() << "Could not create tag for test with tcId:" << id
                        << " tag_size:" << tag.length()
                        << " key_size:" << key.length() << " error:" << result;
          errors++;
        }
      }
    }
  }
  return errors == 0;
}

TEST_F(StatefulHmacBoringSslTest, TestVectors) {
  // Test Hmac with SHA256
  std::unique_ptr<rapidjson::Document> root256 =
      WycheproofUtil::ReadTestVectors("hmac_sha256_test.json");
  ASSERT_TRUE(WycheproofTest(*root256, HashType::SHA256));

  // Test Hmac with SHA512
  std::unique_ptr<rapidjson::Document> root512 =
      WycheproofUtil::ReadTestVectors("hmac_sha512_test.json");
  ASSERT_TRUE(WycheproofTest(*root512, HashType::SHA512));
}
*/

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
