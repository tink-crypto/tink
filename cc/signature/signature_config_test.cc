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

#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/status.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

class DummySignCatalogue : public Catalogue<PublicKeySign> {
 public:
  DummySignCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<PublicKeySign>>>
  GetKeyManager(const std::string& type_url,
                const std::string& primitive_name,
                uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};

class SignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }
};

TEST_F(SignatureConfigTest, testBasic) {
  std::string sign_key_type =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  std::string verify_key_type =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  auto& config = SignatureConfig::Latest();

  EXPECT_EQ(2, SignatureConfig::Latest().entry_size());

  EXPECT_EQ("TinkPublicKeySign", config.entry(0).catalogue_name());
  EXPECT_EQ("PublicKeySign", config.entry(0).primitive_name());
  EXPECT_EQ(sign_key_type, config.entry(0).type_url());
  EXPECT_EQ(true, config.entry(0).new_key_allowed());
  EXPECT_EQ(0, config.entry(0).key_manager_version());

  EXPECT_EQ("TinkPublicKeyVerify", config.entry(1).catalogue_name());
  EXPECT_EQ("PublicKeyVerify", config.entry(1).primitive_name());
  EXPECT_EQ(verify_key_type, config.entry(1).type_url());
  EXPECT_EQ(true, config.entry(1).new_key_allowed());
  EXPECT_EQ(0, config.entry(1).key_manager_version());

  // No key manager before registration.
  auto sign_manager_result =
      Registry::get_key_manager<PublicKeySign>(sign_key_type);
  EXPECT_FALSE(sign_manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, sign_manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = SignatureConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  sign_manager_result = Registry::get_key_manager<PublicKeySign>(sign_key_type);
  EXPECT_TRUE(sign_manager_result.ok()) << sign_manager_result.status();
  EXPECT_TRUE(sign_manager_result.ValueOrDie()->DoesSupport(sign_key_type));

  auto verify_manager_result =
      Registry::get_key_manager<PublicKeyVerify>(verify_key_type);
  EXPECT_TRUE(verify_manager_result.ok()) << verify_manager_result.status();
  EXPECT_TRUE(verify_manager_result.ValueOrDie()->DoesSupport(verify_key_type));
}

TEST_F(SignatureConfigTest, testRegister) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  // Try on empty registry.
  auto status = Config::Register(SignatureConfig::Latest());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());
  auto manager_result = Registry::get_key_manager<PublicKeySign>(key_type);
  EXPECT_FALSE(manager_result.ok());

  // Register and try again.
  status = SignatureConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<PublicKeySign>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();

  // Try Register() again, should succeed (idempotence).
  status = SignatureConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue("TinkPublicKeySign",
                                  new DummySignCatalogue());
  EXPECT_TRUE(status.ok()) << status;
  status = SignatureConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
}

// Tests that the PublicKeySign and PublicKeyVerify wrappers have been properly
// registered and we can wrap primitives.
TEST_F(SignatureConfigTest, WrappersRegistered) {
  ASSERT_TRUE(SignatureConfig::Register().ok());
  auto private_keyset_handle_result =
      KeysetHandle::GenerateNew(SignatureKeyTemplates::EcdsaP256());
  ASSERT_TRUE(private_keyset_handle_result.ok());

  auto public_keyset_handle_result =
      private_keyset_handle_result.ValueOrDie()->GetPublicKeysetHandle();
  ASSERT_TRUE(public_keyset_handle_result.ok());

  auto private_primitive_set_result =
      private_keyset_handle_result.ValueOrDie()->GetPrimitives<PublicKeySign>(
          nullptr);
  ASSERT_TRUE(private_primitive_set_result.ok());

  auto public_primitive_set_result =
      public_keyset_handle_result.ValueOrDie()->GetPrimitives<PublicKeyVerify>(
          nullptr);
  ASSERT_TRUE(public_primitive_set_result.ok());

  auto private_primitive_result =
      Registry::Wrap(std::move(private_primitive_set_result.ValueOrDie()));
  ASSERT_TRUE(private_primitive_result.ok());

  auto public_primitive_result =
      Registry::Wrap(std::move(public_primitive_set_result.ValueOrDie()));
  ASSERT_TRUE(public_primitive_result.ok());

  auto signature_result =
      private_primitive_result.ValueOrDie()->Sign("signed text");
  ASSERT_TRUE(signature_result.ok());

  EXPECT_TRUE(public_primitive_result.ValueOrDie()->Verify(
      signature_result.ValueOrDie(), "signed text").ok());
  EXPECT_FALSE(public_primitive_result.ValueOrDie()->Verify(
      signature_result.ValueOrDie(), "faked text").ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
