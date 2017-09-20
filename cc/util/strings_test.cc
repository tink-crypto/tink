// Copyright 2017 Google Inc.
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

#include <stdarg.h>

#include "cc/util/strings.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

class StringsTest : public ::testing::Test {
};

TEST_F(StringsTest, ToLowercaseTest) {
  EXPECT_EQ("", to_lowercase(""));
  EXPECT_EQ("lowercase string", to_lowercase("lowercase string"));
  EXPECT_EQ("some test string", to_lowercase("Some TeSt sTRInG"));
  EXPECT_EQ("test string with numbers 7393 and other characters *&#()",
      to_lowercase("TeST STRinG WiTH NumBeRS 7393 AnD OTHER CHARACTERs *&#()"));
}

}  // namespace
}  // namespace tink
}  // namespace crypto

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
