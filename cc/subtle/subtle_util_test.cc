// Copyright 2019 Google LLC
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

#include "tink/subtle/subtle_util.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {

using ::testing::Eq;

TEST(SubtleUtilTest, Basic) {
  std::string result = BigEndian32(0x12345678);
  EXPECT_EQ(result[0], 0x12);
  EXPECT_EQ(result[1], 0x34);
  EXPECT_EQ(result[2], 0x56);
  EXPECT_EQ(result[3], 0x78);
}

TEST(SubtleUtilTest, ResizeStringUninitialized) {
  std::string s;
  for (int len = 0; len <= 123; len += 17) {
    int old_len = s.size();
    ResizeStringUninitialized(&s, len);
    for (int i = old_len; i < len; ++i) {
      s[i] = 'a';
    }
    EXPECT_THAT(s, Eq(std::string(len, 'a')));
  }
  for (int len = 100; len >= 0; len -= 20) {
    ResizeStringUninitialized(&s, len);
    EXPECT_THAT(s, Eq(std::string(len, 'a')));
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
