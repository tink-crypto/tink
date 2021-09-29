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

#include "tink/signature/signature_config.h"

#include <list>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "openssl/crypto.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Not;

class SignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(SignatureConfigTest, testBasic) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  RsaSsaPssSignKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(SignatureConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  RsaSsaPssSignKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the PublicKeySignWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeySignWrapperRegistered) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeySign>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("dummy"),
                             key_info)
              .ValueOrDie()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto signature_result = wrapped.ValueOrDie()->Sign("message");
  ASSERT_TRUE(signature_result.ok());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).ValueOrDie();
  EXPECT_EQ(
      signature_result.ValueOrDie(),
      absl::StrCat(prefix,
                   DummyPublicKeySign("dummy").Sign("message").ValueOrDie()));
}


// Tests that the PublicKeyVerifyWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeyVerifyWrapperRegistered) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeyVerify>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyPublicKeyVerify>("dummy"),
                             key_info)
              .ValueOrDie()),
      IsOk());
  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).ValueOrDie();
  std::string signature =
      DummyPublicKeySign("dummy").Sign("message").ValueOrDie();

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  ASSERT_TRUE(wrapped.ValueOrDie()
                  ->Verify(absl::StrCat(prefix, signature), "message")
                  .ok());
}

// FIPS-only mode tests
TEST_F(SignatureConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(SignatureConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(SignatureKeyTemplates::Ed25519());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::Ed25519WithRawOutput());
  // 4096-bit RSA is not validated.
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(),
                Not(IsOk()));
  }
}

TEST_F(SignatureConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(SignatureConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP256());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP256Ieee());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Sha384());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Sha512());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Ieee());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP521());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP521Ieee());
  fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4());
  fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4());

  for (auto key_template : fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(), IsOk());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
