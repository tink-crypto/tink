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

#include "tink/subtle/stateful_cmac_boringssl.h"

#include <cstddef>
#include <string>

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

void EmptyCmac(uint32_t tag_size, std::string key, std::string expected) {
  auto cmac_result =
      StatefulCmacBoringSsl::New(tag_size, util::SecretDataFromStringView(key));
  EXPECT_THAT(cmac_result.status(), IsOk());
  auto cmac = std::move(cmac_result.ValueOrDie());
  auto result = cmac->Finalize();
  EXPECT_THAT(result.status(), IsOk());

  auto tag = result.ValueOrDie();
  EXPECT_EQ(tag.size(), tag_size);
  EXPECT_EQ(tag, expected);
}

TEST(StatefulCmacBoringSslTest, testEmpty) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));

  std::string expected(
      test::HexDecodeOrDie("97dd6e5a882cbd564c39ae7d1c5a31aa"));
  EmptyCmac(kTagSize, key, expected);

  std::string expected_small(test::HexDecodeOrDie("97dd6e5a882cbd564c39"));
  EmptyCmac(kSmallTagSize, key, expected_small);
}

void BasicCmac(uint32_t tag_size, std::string key, std::string data,
               std::string expected) {
  auto cmac_result =
      StatefulCmacBoringSsl::New(tag_size, util::SecretDataFromStringView(key));
  EXPECT_THAT(cmac_result.status(), IsOk());
  auto cmac = std::move(cmac_result.ValueOrDie());

  auto update_result = cmac->Update(data);
  EXPECT_THAT(update_result, IsOk());
  auto result = cmac->Finalize();
  EXPECT_THAT(result.status(), IsOk());

  auto tag = result.ValueOrDie();
  EXPECT_EQ(tag.size(), tag_size);
  EXPECT_EQ(tag, expected);
}

TEST(StatefulCmacBoringSslTest, testBasic) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  std::string data = "Some data to test.";

  std::string expected(
      test::HexDecodeOrDie("c856e183e8dee9bb99402d54c34f3222"));
  BasicCmac(kTagSize, key, data, expected);

  std::string expected_small(test::HexDecodeOrDie("c856e183e8dee9bb9940"));
  BasicCmac(kSmallTagSize, key, data, expected_small);
}

void MultipleUpdateCmac(uint32_t tag_size, std::string key, std::string data1,
                        std::string data2, std::string data3, std::string data4,
                        std::string expected) {
  auto cmac_result =
      StatefulCmacBoringSsl::New(tag_size, util::SecretDataFromStringView(key));
  EXPECT_THAT(cmac_result.status(), IsOk());
  auto cmac = std::move(cmac_result.ValueOrDie());

  auto update_1 = cmac->Update(data1);
  EXPECT_THAT(update_1, IsOk());
  auto update_2 = cmac->Update(data2);
  EXPECT_THAT(update_2, IsOk());
  auto update_3 = cmac->Update(data3);
  EXPECT_THAT(update_3, IsOk());
  auto update_4 = cmac->Update(data4);
  EXPECT_THAT(update_4, IsOk());

  auto result = cmac->Finalize();
  EXPECT_THAT(result.status(), IsOk());

  auto tag = result.ValueOrDie();
  EXPECT_EQ(tag.size(), tag_size);
  EXPECT_EQ(tag, expected);
}

TEST(StatefulCmacBoringSslTest, testMultipleUpdates) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  std::string data1 = "Some ", data2 = "data ", data3 = "to ", data4 = "test.";

  // The tags are the same as the tags in testBasic, since they have the same
  // key and the same input, but testMultipleUpdates uses multiple updates.

  std::string expected(
      test::HexDecodeOrDie("c856e183e8dee9bb99402d54c34f3222"));
  MultipleUpdateCmac(kTagSize, key, data1, data2, data3, data4, expected);

  std::string expected_small(test::HexDecodeOrDie("c856e183e8dee9bb9940"));
  MultipleUpdateCmac(kSmallTagSize, key, data1, data2, data3, data4,
                     expected_small);
}

TEST(StatefulCmacFactoryTest, createsObjects) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  std::string data = "Some data to test.";

  std::string expected(
      test::HexDecodeOrDie("c856e183e8dee9bb99402d54c34f3222"));
  BasicCmac(kTagSize, key, data, expected);
  auto factory = absl::make_unique<StatefulCmacBoringSslFactory>(
      kTagSize, util::SecretDataFromStringView(key));
  auto stateful_cmac_or = factory->Create();
  ASSERT_THAT(stateful_cmac_or.status(), IsOk());
  auto stateful_cmac = std::move(stateful_cmac_or.ValueOrDie());
  EXPECT_THAT(stateful_cmac->Update(data), IsOk());
  auto output_or = stateful_cmac->Finalize();
  ASSERT_THAT(output_or.status(), IsOk());
  auto output = output_or.ValueOrDie();
  EXPECT_THAT(output, StrEq(expected));
}

// Test with test vectors from Wycheproof project.
bool WycheproofTest(const rapidjson::Document &root) {
  int errors = 0;
  for (const rapidjson::Value &test_group : root["testGroups"].GetArray()) {
    // Get the key size in bytes. Wycheproof contains tests for keys of sizes
    // other than 16 or 32, so the test will skip those.
    auto key_size = test_group["keySize"].GetInt();
    if (!(key_size == 16 || key_size == 32)) {
      continue;
    }
    for (const rapidjson::Value &test : test_group["tests"].GetArray()) {
      std::string comment = test["comment"].GetString();
      std::string key = WycheproofUtil::GetBytes(test["key"]);
      std::string msg = WycheproofUtil::GetBytes(test["msg"]);
      std::string tag = WycheproofUtil::GetBytes(test["tag"]);
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string expected = test["result"].GetString();

      auto create_result = StatefulCmacBoringSsl::New(
          tag.length(), util::SecretDataFromStringView(key));
      EXPECT_THAT(create_result.status(), IsOk());
      auto cmac = std::move(create_result.ValueOrDie());

      auto update_result = cmac->Update(msg);
      EXPECT_THAT(update_result, IsOk());

      auto finalize_result = cmac->Finalize();
      auto result = finalize_result.ValueOrDie();

      bool success = result == tag;
      if (success) {
        // std::string result_tag = result.ValueOrDie();
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

TEST(StatefulCmacBoringSslTest, TestVectors) {
  std::unique_ptr<rapidjson::Document> root256 =
      WycheproofUtil::ReadTestVectors("aes_cmac_test.json");
  ASSERT_TRUE(WycheproofTest(*root256));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
