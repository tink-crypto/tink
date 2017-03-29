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

#include "cc/mac.h"
#include "cc/mac/mac_factory.h"
#include "cc/util/status.h"
#include "gtest/gtest.h"

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class MacFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(MacFactoryTest, testBasic) {
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            MacFactory::RegisterStandardKeyTypes().error_code());
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            MacFactory::RegisterLegacyKeyTypes().error_code());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
