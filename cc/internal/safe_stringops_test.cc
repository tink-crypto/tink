// Copyright 2024 Google LLC
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

#include "tink/internal/safe_stringops.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::StrEq;

TEST(MemCopyTest, Regular) {
  char src[] = "hello";
  char dst[] = "world";
  EXPECT_THAT(dst, StrEq("world"));
  static_assert(sizeof(src) == sizeof(dst), "size mismatch");
  EXPECT_EQ(SafeMemCopy(dst, src, sizeof(src)), dst);
  EXPECT_THAT(dst, StrEq("hello"));
}

TEST(MemMoveTest, Regular) {
  char src[] = "hello";
  char dst[] = "world";
  EXPECT_THAT(dst, StrEq("world"));
  static_assert(sizeof(src) == sizeof(dst), "size mismatch");
  EXPECT_EQ(SafeMemMove(dst, src, sizeof(src)), dst);
  EXPECT_THAT(dst, StrEq("hello"));
}

TEST(MemMoveTest, NoMove) {
  char mem[] = "hello";
  EXPECT_THAT(mem, StrEq("hello"));
  EXPECT_EQ(SafeMemMove(mem, mem, sizeof(mem)), mem);
  EXPECT_THAT(mem, StrEq("hello"));
}

TEST(MemmoveTest, OverlapSuffix) {
  char mem[] = "hello";
  EXPECT_THAT(mem, StrEq("hello"));
  EXPECT_EQ(SafeMemMove(&mem[1], mem, sizeof(mem) - 2), &mem[1]);
  EXPECT_THAT(mem, StrEq("hhell"));
}

TEST(MemMoveTest, OverlapPrefix) {
  char mem[] = "hello";
  EXPECT_THAT(mem, StrEq("hello"));
  EXPECT_EQ(SafeMemMove(mem, &mem[1], sizeof(mem) - 2), mem);
  EXPECT_THAT(mem, StrEq("elloo"));
}

TEST(MemEqualsTest, Equal) {
  char a[] = "hello";
  char b[] = "hello";
  EXPECT_NE(a, b);
  static_assert(sizeof(a) == sizeof(b), "size mismatch");
  EXPECT_TRUE(SafeCryptoMemEquals(a, b, sizeof(a)));
  EXPECT_TRUE(SafeCryptoMemEquals(b, a, sizeof(a)));
}

TEST(MemEqualsTest, Unequal) {
  char a[] = "hello";
  char b[] = "hellu";
  EXPECT_NE(a, b);
  static_assert(sizeof(a) == sizeof(b), "size mismatch");
  EXPECT_FALSE(SafeCryptoMemEquals(a, b, sizeof(a)));
  EXPECT_FALSE(SafeCryptoMemEquals(b, a, sizeof(a)));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
