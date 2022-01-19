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
#include "tink/internal/fips_utils.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "openssl/crypto.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class FipsIncompatible {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;
};

class FipsCompatibleWithBoringCrypto {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;
};

TEST(FipsUtilsTest, CompatibilityInNonFipsMode) {
  if (internal::kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(internal::CheckFipsCompatibility<FipsIncompatible>(), IsOk());
  EXPECT_THAT(
      internal::CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(),
      IsOk());
}

TEST(FipsUtilsTest, CompatibilityInFipsMode) {
  if (!internal::kUseOnlyFips || !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should only run in FIPS mode with Boringcrypto available.";
  }

  EXPECT_THAT(internal::CheckFipsCompatibility<FipsIncompatible>(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(
      internal::CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(),
      IsOk());
}

TEST(TinkFipsTest, CompatibilityInFipsModeWithoutBoringCrypto) {
  if (!internal::kUseOnlyFips || FIPS_mode()) {
    GTEST_SKIP() << "Test only run if BoringCrypto module is not available.";
  }

  // In FIPS only mode compatibility checks should disallow algorithms
  // with the FipsCompatibility::kNone flag.
  EXPECT_THAT(internal::CheckFipsCompatibility<FipsIncompatible>(),
              StatusIs(absl::StatusCode::kInternal));

  // FIPS validated implementations are not allowed if BoringCrypto is not
  // available.
  EXPECT_THAT(
      internal::CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(),
      StatusIs(absl::StatusCode::kInternal));
}

}  // namespace

}  // namespace tink
}  // namespace crypto
