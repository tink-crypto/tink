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

#include "tink/util/secret_data.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::testing::AnyOf;
using ::testing::ElementsAreArray;
using ::testing::Eq;

TEST(SecretDataTest, OneByOneInsertion) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41, 0,
                                         52, 56, 6,  12, 127, 13};
  SecretData data;
  for (unsigned char c : kContents) {
    data.push_back(c);
  }
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

TEST(SecretDataTest, SecretDataFromStringViewConstructor) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 124, 16};
  std::string s;
  for (unsigned char c : kContents) {
    s.push_back(c);
  }
  SecretData data = SecretDataFromStringView(s);
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

TEST(SecretDataTest, StringViewFromSecretData) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 124, 16};
  std::string s;
  for (unsigned char c : kContents) {
    s.push_back(c);
  }
  SecretData data = SecretDataFromStringView(s);
  absl::string_view data_view = SecretDataAsStringView(data);
  EXPECT_THAT(data_view, Eq(s));
}

TEST(SecretDataTest, SecretDataCopy) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41, 0,
                                         52, 56, 6,  12, 127, 13};
  SecretData data;
  for (unsigned char c : kContents) {
    data.push_back(c);
  }
  SecretData data_copy = data;
  EXPECT_THAT(data_copy, ElementsAreArray(kContents));
}

TEST(SecretValueTest, DefaultConstructor) {
  SecretValue<int> s;
  EXPECT_THAT(s.value(), Eq(0));
}

TEST(SecretValueTest, Constructor) {
  SecretValue<int> s(102);
  EXPECT_THAT(s.value(), Eq(102));
}

TEST(SecretValueTest, CopyConstructor) {
  SecretValue<int> s(102);
  SecretValue<int> t(s);
  EXPECT_THAT(t.value(), Eq(102));
}

TEST(SecretValueTest, AssignmentOperator) {
  SecretValue<int> s(102);
  SecretValue<int> t(101);
  t = s;
  EXPECT_THAT(t.value(), Eq(102));
}

TEST(SecretValueTest, MoveConstructor) {
  SecretValue<int> s(102);
  SecretValue<int> t(std::move(s));
  EXPECT_THAT(t.value(), Eq(102));
  EXPECT_THAT(s.value(), AnyOf(Eq(0), Eq(102)));
}

TEST(SecretValueTest, MoveAssignment) {
  SecretValue<int> s(102);
  SecretValue<int> t;
  t = std::move(s);
  EXPECT_THAT(t.value(), Eq(102));
  EXPECT_THAT(s.value(), AnyOf(Eq(0), Eq(102)));
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
