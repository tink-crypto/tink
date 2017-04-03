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

#include "cc/subtle/random.h"
#include "gtest/gtest.h"

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class RandomTest : public ::testing::Test {
};

TEST_F(RandomTest, testBasic) {
  EXPECT_EQ("a", Random::GetRandomBytes(1));
  EXPECT_EQ("aaa", Random::GetRandomBytes(3));
  EXPECT_EQ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Random::GetRandomBytes(42));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
