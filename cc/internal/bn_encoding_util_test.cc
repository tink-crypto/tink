// Copyright 2023 Google LLC
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
#include "tink/internal/bn_encoding_util.h"

#include <stddef.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::SizeIs;

TEST(BnEncodingUtilTest, GetValueOfFixedLength) {
  std::vector<std::string> bn_str = {"0000000000000000", "0000000000000001",
                                     "1000000000000000", "ffffffffffffffff",
                                     "0fffffffffffffff", "00ffffffffffffff"};
  for (const std::string& s : bn_str) {
    const std::string bn_bytes = absl::HexStringToBytes(s);
    util::StatusOr<std::string> bn_bytes_fixed_length =
        GetValueOfFixedLength(bn_bytes, 10);

    EXPECT_THAT(bn_bytes_fixed_length,
                IsOkAndHolds(absl::HexStringToBytes(absl::StrCat("0000", s))));
  }
}

TEST(BnEncodingUtilTest, GetValueOfFixedLengthIntegerTooBig) {
  std::string bn_str = "0fffffffffffffff";
  const std::string bn_bytes = absl::HexStringToBytes(bn_str);

  util::StatusOr<std::string> bn_bytes_fixed_length =
      GetValueOfFixedLength(bn_bytes, 2);
  EXPECT_THAT(bn_bytes_fixed_length.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(BnEncodingUtilTest, GetValueOfFixedLengthSameLength) {
  std::string bn_str = "0fffffffffffffff";
  const std::string bn_bytes = absl::HexStringToBytes(bn_str);

  util::StatusOr<std::string> bn_bytes_fixed_length =
      GetValueOfFixedLength(bn_bytes, 8);

  EXPECT_THAT(bn_bytes_fixed_length, IsOkAndHolds(bn_bytes));
}

TEST(BnEncodingUtilTest, CreateBigIntegerObjectOfFixedLength) {
  constexpr absl::string_view big_integer_hex_256 =
      "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628"
      "d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1"
      "aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74b"
      "f861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d"
      "7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2"
      "d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b"
      "0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e"
      "43cad84d";

  const std::string big_integer_bytes_256 =
      absl::HexStringToBytes(big_integer_hex_256);
  util::StatusOr<std::string> big_integer_bytes_fixed_length =
      GetValueOfFixedLength(big_integer_bytes_256, 258);

  BigInteger big_integer(big_integer_bytes_256);
  EXPECT_THAT(big_integer.SizeInBytes(), Eq(256));
  EXPECT_THAT(big_integer.GetValue(), Eq(big_integer_bytes_256));

  EXPECT_THAT(*big_integer_bytes_fixed_length, SizeIs(258));
  EXPECT_THAT(
      big_integer_bytes_fixed_length,
      IsOkAndHolds(absl::HexStringToBytes(
          "0000b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc"
          "3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6"
          "d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86d"
          "db589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0"
          "adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce716"
          "1e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e"
          "888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623ca"
          "dc0f097af573261c98c8400aa12af38e43cad84d")));

  BigInteger same_big_integer(*big_integer_bytes_fixed_length);
  EXPECT_THAT(big_integer, Eq(same_big_integer));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
