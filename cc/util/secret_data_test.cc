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

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::testing::ElementsAreArray;

TEST(SecretDataTest, OneByOneInsertion) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41, 52, 56, 6, 12, 42};
  SecretData data;
  for (unsigned char c : kContents) {
    data.push_back(c);
  }
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
