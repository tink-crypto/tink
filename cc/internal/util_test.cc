// Copyright 2021 Google LLC
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
#include "tink/internal/util.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr absl::string_view kLongString =
    "a long buffer with \n several \n newlines";

TEST(UtilTest, EnsureStringNonNull) {
  // Purposely create a string_view from nullptr.
  auto null_str = absl::string_view(nullptr, 0);
  EXPECT_EQ(EnsureStringNonNull(null_str), absl::string_view(""));
  auto uninit_str = absl::string_view();
  EXPECT_EQ(EnsureStringNonNull(uninit_str), absl::string_view(""));
  auto regular_str = absl::string_view("This is a non-empty non-null str");
  EXPECT_EQ(EnsureStringNonNull(regular_str), regular_str);
}

TEST(BuffersOverlapTest, BufferOverlapEmpty) {
  absl::string_view empty = "";
  EXPECT_FALSE(BuffersOverlap(empty, empty));
  EXPECT_FALSE(BuffersOverlap(empty, ""));
}

TEST(BuffersOverlapTest, BufferOverlapSeparate) {
  absl::string_view first = "first";
  absl::string_view second = "second";
  EXPECT_FALSE(BuffersOverlap(first, second));
  EXPECT_TRUE(BuffersOverlap(first, first));
}

TEST(BuffersOverlapTest, BufferOverlap) {
  absl::string_view long_buffer = kLongString;

  EXPECT_TRUE(BuffersOverlap(long_buffer, long_buffer));

  EXPECT_TRUE(
      BuffersOverlap(long_buffer.substr(0, 10), long_buffer.substr(9, 5)));
  EXPECT_FALSE(
      BuffersOverlap(long_buffer.substr(0, 10), long_buffer.substr(10, 5)));

  EXPECT_TRUE(
      BuffersOverlap(long_buffer.substr(9, 5), long_buffer.substr(0, 10)));
  EXPECT_FALSE(
      BuffersOverlap(long_buffer.substr(10, 5), long_buffer.substr(0, 10)));
}

TEST(BuffersAreIdenticalTest, EmptyString) {
  std::string empty_str = "";
  absl::string_view empty = "";
  EXPECT_FALSE(BuffersAreIdentical(empty, empty));
  EXPECT_FALSE(BuffersAreIdentical(absl::string_view(empty_str),
                                   absl::string_view(empty_str)));
  EXPECT_FALSE(BuffersAreIdentical(empty, ""));
  EXPECT_FALSE(BuffersAreIdentical(empty, absl::string_view(empty_str)));
}

TEST(BuffersAreIdenticalTest, BuffersAreIdentical) {
  auto some_string = std::string(kLongString);
  auto buffer = absl::string_view(some_string);
  EXPECT_TRUE(BuffersAreIdentical(buffer, buffer));
  // Make sure BuffersAreIdentical is not checking for string equality.
  std::string identical_string = some_string;
  EXPECT_FALSE(
      BuffersAreIdentical(buffer, absl::string_view(identical_string)));
}

TEST(BuffersAreIdenticalTest, PartialOverlapFails) {
  auto some_string = std::string(kLongString);
  auto buffer = absl::string_view(some_string);
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(0, 10), buffer.substr(9, 5)));
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(0, 10), buffer.substr(10, 5)));
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(9, 5), buffer.substr(0, 10)));
  EXPECT_FALSE(BuffersAreIdentical(buffer.substr(10, 5), buffer.substr(0, 10)));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
