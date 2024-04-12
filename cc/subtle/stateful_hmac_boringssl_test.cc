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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/log.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr size_t kTagSize = 16;
constexpr size_t kSmallTagSize = 10;

using crypto::tink::test::HexDecodeOrDie;
using crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::SizeIs;

struct TestVector {
  TestVector(std::string test_name, std::string hex_key, HashType hash_type,
              uint32_t tag_size, std::string message, std::string hex_tag)
      : test_name(test_name),
        hex_key(hex_key),
        hash_type(hash_type),
        tag_size(tag_size),
        message(message),
        hex_tag(hex_tag) {}
  std::string test_name;
  std::string hex_key;
  HashType hash_type;
  uint32_t tag_size;
  std::string message;
  std::string hex_tag;
};

using StatefulHmacBoringSslTest = testing::TestWithParam<TestVector>;

std::vector<TestVector> GetTestVectors() {
  return {
      TestVector(/*test_name=*/"EmptyMsgSha224",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA224, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"4e496054842798a861acb67a9fe85fb7"),
      TestVector(/*test_name=*/"EmptyMsgSha256",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"07eff8b326b7798c9ccfcbdbe579489a"),
      TestVector(/*test_name=*/"EmptyMsgSha384",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA384, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"6a0fdc1c54c664ad91c7c157d2670c5d"),
      TestVector(/*test_name=*/"EmptyMsgSha512",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"2fec800ca276c44985a35aec92067e5e"),
      TestVector(/*test_name=*/"EmptyMsgSha256TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/10,
                 /*message=*/"",
                 /*hex_tag=*/"07eff8b326b7798c9ccf"),
      TestVector(/*test_name=*/"EmptyMsgSha512TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/10,
                 /*message=*/"",
                 /*hex_tag=*/"2fec800ca276c44985a3"),
      TestVector(/*test_name=*/"BasicMessageSha256",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/16,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"1d6eb74bc283f7947e92c72bd985ce6e"),
      TestVector(/*test_name=*/"BasicMessageSha512",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/16,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"72b8ff800f57f9aeec41265a29b69b6a"),
      TestVector(/*test_name=*/"BasicMessageSha256TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/10,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"1d6eb74bc283f7947e92"),
      TestVector(/*test_name=*/"BasicMessageSha512TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/10,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"72b8ff800f57f9aeec41"),
      TestVector(/*test_name=*/"LongMessageSha224",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA224, /*tag_size=*/16,
                 /*message=*/
                 "Some very long message which can be split in "
                 "multiple ways. The contents are not really important, "
                 "but we want the message to be quite long",
                 /*hex_tag=*/"0165b6a416a44d1558816f75ff1e13f3"),
      TestVector(/*test_name=*/"LongMessageSha256",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/16,
                 /*message=*/
                 "Some very long message which can be split in "
                 "multiple ways. The contents are not really important, "
                 "but we want the message to be quite long",
                 /*hex_tag=*/"aa85d0f6f3c46330e65f814535f6ad8e"),
  };
}

TEST_P(StatefulHmacBoringSslTest, OnlyEmptyMessages) {
  TestVector test_vector = GetParam();
  if (!test_vector.message.empty()) {
    GTEST_SKIP() << "Test tests only empty messages";
  }
  util::StatusOr<std::unique_ptr<StatefulMac>> hmac_result =
      StatefulHmacBoringSsl::New(
          test_vector.hash_type, test_vector.tag_size,
          util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  ASSERT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  util::StatusOr<std::string> tag = hmac->Finalize();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(*tag), Eq(test_vector.hex_tag));
}

TEST_P(StatefulHmacBoringSslTest, SingleUpdate) {
  TestVector test_vector = GetParam();
  auto hmac_result = StatefulHmacBoringSsl::New(
      test_vector.hash_type, test_vector.tag_size,
      util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  ASSERT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  ASSERT_THAT(hmac->Update(test_vector.message), IsOk());
  util::StatusOr<std::string> tag = hmac->Finalize();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(*tag), Eq(test_vector.hex_tag));
}

TEST_P(StatefulHmacBoringSslTest, MultipleUpdates) {
  TestVector test_vector = GetParam();
  auto hmac_result = StatefulHmacBoringSsl::New(
      test_vector.hash_type, test_vector.tag_size,
      util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  ASSERT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  absl::string_view remaining_message = test_vector.message;
  LOG(INFO) << "Starting to update";
  while (!remaining_message.empty()) {
    int random_byte = Random::GetRandomUInt8() % 15;
    int amount_to_consume =
        std::min<int>(remaining_message.size(), random_byte);
    LOG(INFO) << "Consuming " << amount_to_consume << " bytes";
    ASSERT_THAT(hmac->Update(remaining_message.substr(0, amount_to_consume)),
                IsOk());
    remaining_message.remove_prefix(amount_to_consume);
  }
  LOG(INFO) << "Done updating ";
  util::StatusOr<std::string> tag = hmac->Finalize();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(*tag), Eq(test_vector.hex_tag));
}

TEST_P(StatefulHmacBoringSslTest, MultipleUpdatesObjectFromFactory) {
  TestVector test_vector = GetParam();
  auto factory = absl::make_unique<StatefulHmacBoringSslFactory>(
      test_vector.hash_type, test_vector.tag_size,
      util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  util::StatusOr<std::unique_ptr<StatefulMac>> hmac =
      factory->Create();
  ASSERT_THAT(hmac, IsOk());
  absl::string_view remaining_message = test_vector.message;
  while (!remaining_message.empty()) {
    int random_byte = Random::GetRandomUInt8() % 15;
    int amount_to_consume =
        std::min<int>(remaining_message.size(), random_byte);
    ASSERT_THAT((*hmac)->Update(remaining_message.substr(0, amount_to_consume)),
                IsOk());
    remaining_message.remove_prefix(amount_to_consume);
  }
  util::StatusOr<std::string> tag = (*hmac)->Finalize();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(*tag), Eq(test_vector.hex_tag));
}

INSTANTIATE_TEST_SUITE_P(
    StatefulHmacBoringSslTest, StatefulHmacBoringSslTest,
    testing::ValuesIn(GetTestVectors()),
    [](const testing::TestParamInfo<TestVector>& info) {
      return info.param.test_name;
    });

TEST(StatefulHmacBoringSslTest, InvalidKeySizes) {
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
