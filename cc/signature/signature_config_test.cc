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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/config.h"
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

class SignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(SignatureConfigTest, testBasic) {
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
  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeySign>>();
  ASSERT_THAT(primitive_set->set_primary(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("dummy"), key)
          .ValueOrDie()), IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto signature_result = wrapped.ValueOrDie()->Sign("message");
  ASSERT_TRUE(signature_result.ok());

  std::string prefix = CryptoFormat::get_output_prefix(key).ValueOrDie();
  EXPECT_EQ(
      signature_result.ValueOrDie(),
      absl::StrCat(prefix,
                   DummyPublicKeySign("dummy").Sign("message").ValueOrDie()));
}


// Tests that the PublicKeyVerifyWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeyVerifyWrapperRegistered) {
  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeyVerify>>();
  ASSERT_THAT(primitive_set->set_primary(
                  primitive_set
                      ->AddPrimitive(
                          absl::make_unique<DummyPublicKeyVerify>("dummy"), key)
                      .ValueOrDie()),
              IsOk());
  std::string prefix = CryptoFormat::get_output_prefix(key).ValueOrDie();
  std::string signature =
      DummyPublicKeySign("dummy").Sign("message").ValueOrDie();

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  ASSERT_TRUE(wrapped.ValueOrDie()
                  ->Verify(absl::StrCat(prefix, signature), "message")
                  .ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
