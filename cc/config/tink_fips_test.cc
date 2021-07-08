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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "openssl/crypto.h"
#include "tink/aead/aead_config.h"
#include "tink/internal/fips_utils.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using testing::Eq;
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

TEST(TinkFipsTest, CompatibilityChecksWithBoringCrypto) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Test only run if BoringCrypto module is available.";
  }

  Registry::Reset();

  // Tink is not build in FIPS mode, but the FIPS mode is enabled at runtime.
  EXPECT_THAT(crypto::tink::RestrictToFips(), IsOk());

  // In FIPS only mode compatibility checks should disallow algorithms
  // with the FipsCompatibility::kNone flag.
  EXPECT_THAT(internal::CheckFipsCompatibility<FipsIncompatible>(),
              StatusIs(util::error::INTERNAL));

  // FIPS validated implementations should still be allowed.
  EXPECT_THAT(
      internal::CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(),
      IsOk());

  internal::UnSetFipsRestricted();
}

TEST(TinkFipsTest, CompatibilityChecksWithoutBoringCrypto) {
  if (FIPS_mode()) {
    GTEST_SKIP() << "Test only run if BoringCrypto module is not available.";
  }

  Registry::Reset();

  // Tink is not build in FIPS mode, but the FIPS mode is enabled at runtime.
  EXPECT_THAT(crypto::tink::RestrictToFips(), IsOk());

  // In FIPS only mode compatibility checks should disallow algorithms
  // with the FipsCompatibility::kNone flag.
  EXPECT_THAT(internal::CheckFipsCompatibility<FipsIncompatible>(),
              StatusIs(util::error::INTERNAL));

  // FIPS validated implementations are not allowed if BoringCrypto is not
  // available.
  EXPECT_THAT(
      internal::CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(),
      StatusIs(util::error::INTERNAL));

  internal::UnSetFipsRestricted();
}

TEST(TinkFipsTest, FailIfRegistryNotEmpty) {
  if (internal::kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  Registry::Reset();
  internal::UnSetFipsRestricted();

  EXPECT_THAT(AeadConfig::Register(), IsOk());
  EXPECT_THAT(crypto::tink::RestrictToFips(), StatusIs(util::error::INTERNAL));
}

}  // namespace

}  // namespace tink
}  // namespace crypto
