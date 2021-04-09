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
#include "openssl/crypto.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

TEST(TinkFipsTest, FlagCorrectlySet) {
  EXPECT_THAT(kUseOnlyFips, testing::Eq(true));
}

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

TEST(TinkFipsTest, CompatibilityChecksWithBoringCrypto) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Test only run if BoringCrypto module is available.";
  }

  // In FIPS only mode compatibility checks should disallow algorithms
  // with the FipsCompatibility::kNone flag.
  EXPECT_THAT(CheckFipsCompatibility<FipsIncompatible>(),
              StatusIs(util::error::INTERNAL));

  // FIPS validated implementations should still be allowed.
  EXPECT_THAT(CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(), IsOk());
}

TEST(TinkFipsTest, CompatibilityChecksWithoutBoringCrypto) {
  if (FIPS_mode()) {
    GTEST_SKIP() << "Test only run if BoringCrypto module is not available.";
  }

  // In FIPS only mode compatibility checks should disallow algorithms
  // with the FipsCompatibility::kNone flag.
  EXPECT_THAT(CheckFipsCompatibility<FipsIncompatible>(),
              StatusIs(util::error::INTERNAL));

  // FIPS validated implementations are not allowed if BoringCrypto is not
  // available.
  EXPECT_THAT(CheckFipsCompatibility<FipsCompatibleWithBoringCrypto>(),
              StatusIs(util::error::INTERNAL));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
