// Copyright 2017 Google Inc.
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

#include "tink/subtle/random.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class RandomTest : public ::testing::Test {};

TEST_F(RandomTest, testBasic) {
  int numTests = 32;
  std::set<std::string> rand_strings;
  for (int i = 0; i < numTests; i++) {
    std::string s = Random::GetRandomBytes(16);
    EXPECT_EQ(16, s.length());
    rand_strings.insert(s);
  }
  EXPECT_EQ(numTests, rand_strings.size());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
