// Copyright 2023 Google Inc.
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

#include "tink/jwt/jwt_signature_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/config/global_registry.h"
#include "tink/internal/fips_utils.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Not;

class JwtSignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(JwtSignatureConfigTest, FailIfAndOnlyIfInInvalidFipsState) {
  // If FIPS is enabled, then we need FIPS also to be enabled in BoringSSL.
  // Otherwise we are in an invalid state and must fail.
  bool invalid_fips_state =
      internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl();

  if (invalid_fips_state) {
    EXPECT_THAT(JwtSignatureRegister(), Not(IsOk()));

    EXPECT_THAT(KeysetHandle::GenerateNew(JwtEs256Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtRs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtPs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
  } else {
    EXPECT_THAT(JwtSignatureRegister(), IsOk());

    EXPECT_THAT(KeysetHandle::GenerateNew(JwtEs256Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtRs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtPs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
