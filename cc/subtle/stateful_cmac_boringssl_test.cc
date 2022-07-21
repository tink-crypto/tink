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
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr size_t kTagSize = 16;
constexpr size_t kSmallTagSize = 10;

constexpr absl::string_view kKeyHex = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kData = "Some data to test.";
constexpr absl::string_view kCmacOnEmptyInputRegularTagSizeHex =
    "97dd6e5a882cbd564c39ae7d1c5a31aa";
constexpr absl::string_view kCmacOnEmptyInputSmallTagSizeHex =
    "97dd6e5a882cbd564c39";
constexpr absl::string_view kCmacOnDataRegularTagSizeHex =
    "c856e183e8dee9bb99402d54c34f3222";
constexpr absl::string_view kCmacOnDataSmallTagSizeHex = "c856e183e8dee9bb9940";

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(StatefulCmacBoringSslTest, CmacEmptyInputRegularTagSize) {
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT(
      (*cmac)->Finalize(),
      IsOkAndHolds(absl::HexStringToBytes(kCmacOnEmptyInputRegularTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest, CmacEmptyInputSmallTag) {
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kSmallTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT(
      (*cmac)->Finalize(),
      IsOkAndHolds(absl::HexStringToBytes(kCmacOnEmptyInputSmallTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest, CmacSomeDataRegularTagSize) {
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(kData), IsOk());
  EXPECT_THAT(
      (*cmac)->Finalize(),
      IsOkAndHolds(absl::HexStringToBytes(kCmacOnDataRegularTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest, CmacSomeDataSmallTag) {
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kSmallTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(kData), IsOk());
  EXPECT_THAT((*cmac)->Finalize(),
              IsOkAndHolds(absl::HexStringToBytes(kCmacOnDataSmallTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest,
     CmacMultipleUpdatesSameAsOneForWholeInputRegularTagSize) {
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  for (const std::string &token : {"Some ", "data ", "to ", "test."}) {
    EXPECT_THAT((*cmac)->Update(token), IsOk());
  }
  EXPECT_THAT(
      (*cmac)->Finalize(),
      IsOkAndHolds(absl::HexStringToBytes(kCmacOnDataRegularTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest,
     CmacMultipleUpdatesSameAsOneForWholeInputSmallTagSize) {
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kSmallTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  for (const std::string &token : {"Some ", "data ", "to ", "test."}) {
    EXPECT_THAT((*cmac)->Update(token), IsOk());
  }
  EXPECT_THAT((*cmac)->Finalize(),
              IsOkAndHolds(absl::HexStringToBytes(kCmacOnDataSmallTagSizeHex)));
}

TEST(StatefulCmacFactoryTest, FactoryGeneratesValidInstances) {
  auto factory = absl::make_unique<StatefulCmacBoringSslFactory>(
      kTagSize,
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex)));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac = factory->Create();
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(kData), IsOk());
  EXPECT_THAT(
      (*cmac)->Finalize(),
      IsOkAndHolds(absl::HexStringToBytes(kCmacOnDataRegularTagSizeHex)));
}

struct StatefulCmacTestVector {
  std::string key;
  std::string msg;
  std::string tag;
  std::string id;
  std::string expected_result;
};

// Reads the Wycheproof test vectors for AES-CMAC.
std::vector<StatefulCmacTestVector> GetWycheproofCmakeTestVectors() {
  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors("aes_cmac_test.json");
  std::vector<StatefulCmacTestVector> test_vectors;
  for (const rapidjson::Value &test_group : (*root)["testGroups"].GetArray()) {
    // Ignore test vectors of invalid key sizes; valid sizes are {16, 32} bytes.
    int key_size_bits = test_group["keySize"].GetInt();
    if (key_size_bits != 128 && key_size_bits != 256) {
      continue;
    }
    for (const rapidjson::Value &test : test_group["tests"].GetArray()) {
      test_vectors.push_back({
          /*key=*/WycheproofUtil::GetBytes(test["key"]),
          /*msg=*/WycheproofUtil::GetBytes(test["msg"]),
          /*tag=*/WycheproofUtil::GetBytes(test["tag"]),
          /*id=*/absl::StrCat(test["tcId"].GetInt()),
          /*expected_result=*/test["result"].GetString(),
      });
    }
  }
  return test_vectors;
}

using StatefulCmacBoringSslWycheproofTest =
    TestWithParam<StatefulCmacTestVector>;

TEST_P(StatefulCmacBoringSslWycheproofTest, WycheproofTest) {
  StatefulCmacTestVector test_vector = GetParam();

  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeyHex));
  util::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(
          test_vector.tag.length(),
          util::SecretDataFromStringView(test_vector.key));
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(test_vector.msg), IsOk());

  if (test_vector.expected_result == "invalid") {
    EXPECT_THAT((*cmac)->Finalize(), Not(IsOkAndHolds(test_vector.tag)));
  } else {
    EXPECT_THAT((*cmac)->Finalize(), IsOkAndHolds(test_vector.tag));
  }
}

INSTANTIATE_TEST_SUITE_P(StatefulCmacBoringSslWycheproofTest,
                         StatefulCmacBoringSslWycheproofTest,
                         ValuesIn(GetWycheproofCmakeTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
