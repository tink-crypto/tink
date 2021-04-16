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
#include "tink/config/tink_fips.h"

#include "tink/internal/fips_utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {

namespace {

using testing::Eq;

// All tests in this file assume that Tink is not build in FIPS mode.
TEST(TinkFipsTest, FipsEnabledWhenBuiltInFipsMode) {
  // Check if the built flag is set.
  if (!internal::kUseOnlyFips) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(IsFipsModeEnabled(), Eq(true));
}

TEST(TinkFipsTest, FipsDisabledWhenNotBuildInFipsMode) {
  // Check if the built flag is set.
  if (internal::kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(IsFipsModeEnabled(), Eq(false));
}

}  // namespace

}  // namespace tink
}  // namespace crypto
