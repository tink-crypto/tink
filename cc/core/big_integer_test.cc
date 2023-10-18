// Copyright 2023 Google LLC
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

#include "tink/big_integer.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {

using ::testing::Eq;

constexpr absl::string_view kHexBigInt =
    "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628"
    "d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa"
    "3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861"
    "075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da386"
    "8e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca80"
    "59e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8"
    "647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d";

constexpr absl::string_view kHexBigIntPadded =
    "0000b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3"
    "e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63"
    "d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74b"
    "f861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7d"
    "a3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bb"
    "ca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db"
    "09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84"
    "d";

TEST(BigIntegerTest, CreateAndGet) {
  const std::string big_integer_bytes = absl::HexStringToBytes(kHexBigInt);
  BigInteger big_integer(big_integer_bytes);

  EXPECT_THAT(big_integer.SizeInBytes(), Eq(256));
  EXPECT_THAT(big_integer.GetValue(), Eq(big_integer_bytes));
}

TEST(BigIntegerTest, CreateAndGetPadded) {
  const std::string big_integer_bytes = absl::HexStringToBytes(kHexBigInt);
  const std::string padded_big_integer_bytes =
      absl::HexStringToBytes(kHexBigIntPadded);
  BigInteger from_padded_big_integer(padded_big_integer_bytes);

  EXPECT_THAT(from_padded_big_integer.SizeInBytes(), Eq(256));
  EXPECT_FALSE(from_padded_big_integer.GetValue() == padded_big_integer_bytes);
  EXPECT_THAT(from_padded_big_integer.GetValue(), Eq(big_integer_bytes));
}

TEST(BigIntegerTest, CreateAndGetEmptyStringWorks) {
  const std::string empty_string = "";
  BigInteger big_integer(empty_string);

  EXPECT_THAT(big_integer.SizeInBytes(), Eq(0));
  EXPECT_THAT(big_integer.GetValue(), Eq(""));
}

TEST(BigIntegerTest, CreateAndGetNullCharactersWorks) {
  const std::string empty_string = "\0\0\0";
  BigInteger big_integer(empty_string);

  EXPECT_THAT(big_integer.SizeInBytes(), Eq(0));
  EXPECT_THAT(big_integer.GetValue(), Eq(""));
}

TEST(BigIntegerTest, Equals) {
  const std::string big_integer_bytes = absl::HexStringToBytes(kHexBigInt);
  BigInteger big_integer(big_integer_bytes);
  BigInteger same_big_integer(big_integer_bytes);

  EXPECT_TRUE(big_integer == same_big_integer);
  EXPECT_TRUE(same_big_integer == big_integer);
  EXPECT_FALSE(big_integer != same_big_integer);
  EXPECT_FALSE(same_big_integer != big_integer);
}

TEST(BigIntegerTest, EqualsPadded) {
  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger padded_big_integer(absl::HexStringToBytes(kHexBigIntPadded));

  EXPECT_TRUE(big_integer == padded_big_integer);
  EXPECT_TRUE(padded_big_integer == big_integer);
  EXPECT_FALSE(big_integer != padded_big_integer);
  EXPECT_FALSE(padded_big_integer != big_integer);
}

TEST(BigIntegerTest, NotEquals) {
  const std::string other_big_integer_value_256 = absl::HexStringToBytes(
      "00c2410a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e6"
      "28d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63"
      "d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b7"
      "4bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b05"
      "5d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463"
      "e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc"
      "5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af3"
      "8e43cad84d");

  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger diff_big_integer(other_big_integer_value_256);

  EXPECT_THAT(big_integer.SizeInBytes(), Eq(256));
  EXPECT_THAT(diff_big_integer.SizeInBytes(), Eq(256));

  EXPECT_FALSE(big_integer == diff_big_integer);
  EXPECT_FALSE(diff_big_integer == big_integer);
  EXPECT_TRUE(big_integer != diff_big_integer);
  EXPECT_TRUE(diff_big_integer != big_integer);
}

TEST(BigIntegerTest, NotEqualsDifferentSize) {
  constexpr absl::string_view other_big_integer_value =
      "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628"
      "d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1"
      "aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74b"
      "f861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d"
      "7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2"
      "d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b"
      "0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e"
      "43cad84dbfff";
  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger diff_big_integer(absl::HexStringToBytes(other_big_integer_value));

  EXPECT_THAT(big_integer.SizeInBytes(), Eq(256));
  EXPECT_THAT(diff_big_integer.SizeInBytes(), Eq(258));

  EXPECT_FALSE(big_integer == diff_big_integer);
  EXPECT_FALSE(diff_big_integer == big_integer);
  EXPECT_TRUE(big_integer != diff_big_integer);
  EXPECT_TRUE(diff_big_integer != big_integer);
}

TEST(BigIntegerTest, CopyConstructor) {
  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger copy(big_integer);

  EXPECT_THAT(copy.SizeInBytes(), Eq(256));
  EXPECT_THAT(copy.GetValue(), Eq(big_integer.GetValue()));
}

TEST(BigIntegerTest, CopyAssignment) {
  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger copy = big_integer;

  EXPECT_THAT(copy.SizeInBytes(), Eq(256));
  EXPECT_THAT(copy.GetValue(), Eq(big_integer.GetValue()));
}

TEST(BigIntegerTest, MoveConstructor) {
  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger move(std::move(big_integer));

  EXPECT_THAT(move.SizeInBytes(), Eq(256));
  EXPECT_THAT(move.GetValue(), Eq(absl::HexStringToBytes(kHexBigInt)));
}

TEST(BigIntegerTest, MoveAssignment) {
  BigInteger big_integer(absl::HexStringToBytes(kHexBigInt));
  BigInteger move = std::move(big_integer);

  EXPECT_THAT(move.SizeInBytes(), Eq(256));
  EXPECT_THAT(move.GetValue(), Eq(absl::HexStringToBytes(kHexBigInt)));
}

}  // namespace tink
}  // namespace crypto
