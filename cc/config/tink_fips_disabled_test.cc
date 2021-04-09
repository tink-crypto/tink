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
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/config/tink_fips.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using testing::Eq;

TEST(TinkFipsTest, FlagCorrectlySet) { EXPECT_THAT(kUseOnlyFips, Eq(false)); }

class FipsIncompatible {
 public:
  static constexpr crypto::tink::FipsCompatibility kFipsStatus =
      crypto::tink::FipsCompatibility::kNotFips;
};

class FipsCompatibleWithBoringCrypto {
 public:
  static constexpr crypto::tink::FipsCompatibility kFipsStatus =
      crypto::tink::FipsCompatibility::kRequiresBoringCrypto;
};

TEST(TinkFipsTest, Compatibility) {
  // With FIPS only mode disabled no restrictions should apply.
  EXPECT_THAT(CheckFipsCompatibility<FipsIncompatible>(), IsOk());
  EXPECT_THAT(CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
