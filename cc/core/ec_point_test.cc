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
////////////////////////////////////////////////////////////////////////////////

#include "tink/ec_point.h"

#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/big_integer.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace {

using ::testing::Eq;

TEST(EcPointTest, Create) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);

  ASSERT_THAT(point.GetX(), Eq(x));
  ASSERT_THAT(point.GetY(), Eq(y));
}

TEST(EcPointTest, CopyConstructor) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint copy(point);

  ASSERT_THAT(copy.GetX(), Eq(x));
  ASSERT_THAT(copy.GetY(), Eq(y));
}

TEST(EcPointTest, CopyAssignment) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint copy = point;

  ASSERT_THAT(copy.GetX(), Eq(x));
  ASSERT_THAT(copy.GetY(), Eq(y));
}

TEST(EcPointTest, MoveConstructor) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint moved(std::move(point));

  ASSERT_THAT(moved.GetX(), Eq(x));
  ASSERT_THAT(moved.GetY(), Eq(y));
}

TEST(EcPointTest, MoveAssignment) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint moved = std::move(point);

  ASSERT_THAT(moved.GetX(), Eq(x));
  ASSERT_THAT(moved.GetY(), Eq(y));
}

TEST(EcPointTest, Equals) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint other_point(x, y);

  EXPECT_TRUE(point == other_point);
  EXPECT_TRUE(other_point == point);
  EXPECT_FALSE(point != other_point);
  EXPECT_FALSE(other_point != point);
}

TEST(EcPointTest, DifferentXNotEqual) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger other_x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint other_point(other_x, y);

  EXPECT_TRUE(point != other_point);
  EXPECT_TRUE(other_point != point);
  EXPECT_FALSE(point == other_point);
  EXPECT_FALSE(other_point == point);
}

TEST(EcPointTest, DifferentYNotEqual) {
  BigInteger x = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger y = BigInteger(subtle::Random::GetRandomBytes(32));
  BigInteger other_y = BigInteger(subtle::Random::GetRandomBytes(32));

  EcPoint point(x, y);
  EcPoint other_point(x, other_y);

  EXPECT_TRUE(point != other_point);
  EXPECT_TRUE(other_point != point);
  EXPECT_FALSE(point == other_point);
  EXPECT_FALSE(other_point == point);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
