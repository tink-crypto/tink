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

#include "tink/experimental/pqcrypto/signature/signature_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config/tink_fips.h"
#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/sphincs_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/falcon_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/falcon_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class PcqSignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(PcqSignatureConfigTest, CheckDilithium) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used";
  }

  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  DilithiumSignKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  DilithiumVerifyKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(PqSignatureConfigRegister(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  DilithiumSignKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  DilithiumVerifyKeyManager().get_key_type())
                  .status(),
              IsOk());
}

TEST_F(PcqSignatureConfigTest, CheckSphincs) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used";
  }

  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  SphincsSignKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  SphincsVerifyKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(PqSignatureConfigRegister(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  SphincsSignKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  SphincsVerifyKeyManager().get_key_type())
                  .status(),
              IsOk());
}

TEST_F(PcqSignatureConfigTest, CheckFalcon) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used";
  }

  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  FalconSignKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  FalconVerifyKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(PqSignatureConfigRegister(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  FalconSignKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  FalconVerifyKeyManager().get_key_type())
                  .status(),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
