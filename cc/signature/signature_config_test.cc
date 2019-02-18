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
#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"
#include "absl/memory/memory.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;

class DummySignCatalogue : public Catalogue<PublicKeySign> {
 public:
  DummySignCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<PublicKeySign>>>
  GetKeyManager(const std::string& type_url, const std::string& primitive_name,
                uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};

class SignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(SignatureConfigTest, testBasic) {
  std::vector<std::string> sign_key_types;
  sign_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
  sign_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey");
  sign_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey");
  sign_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey");

  std::vector<std::string> verify_key_types;
  verify_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey");
  verify_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey");
  verify_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey");
  verify_key_types.push_back(
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey");

  const size_t total_key_types =
      sign_key_types.size() + verify_key_types.size();

  auto& config = SignatureConfig::Latest();

  EXPECT_EQ(total_key_types, SignatureConfig::Latest().entry_size());
  EXPECT_EQ(sign_key_types.size(), verify_key_types.size());

  for (int i = 0; i < SignatureConfig::Latest().entry_size(); i += 2) {
    std::string sign_key_type = sign_key_types[i / 2];
    EXPECT_EQ("TinkPublicKeySign", config.entry(i).catalogue_name());
    EXPECT_EQ("PublicKeySign", config.entry(i).primitive_name());
    EXPECT_EQ(sign_key_type, config.entry(i).type_url());
    EXPECT_EQ(true, config.entry(i).new_key_allowed());
    EXPECT_EQ(0, config.entry(i).key_manager_version());

    std::string verify_key_type = verify_key_types[i / 2];
    EXPECT_EQ("TinkPublicKeyVerify", config.entry(i + 1).catalogue_name());
    EXPECT_EQ("PublicKeyVerify", config.entry(i + 1).primitive_name());
    EXPECT_EQ(verify_key_type, config.entry(i + 1).type_url());
    EXPECT_EQ(true, config.entry(i + 1).new_key_allowed());
    EXPECT_EQ(0, config.entry(i + 1).key_manager_version());
  }

  // No key manager before registration.
  for (const auto& sign_key_type : sign_key_types) {
    auto sign_manager_result =
        Registry::get_key_manager<PublicKeySign>(sign_key_type);
    EXPECT_FALSE(sign_manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND,
              sign_manager_result.status().error_code());
  }
  for (const auto& verify_key_type : verify_key_types) {
    auto verify_manager_result =
        Registry::get_key_manager<PublicKeyVerify>(verify_key_type);
    EXPECT_FALSE(verify_manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND,
              verify_manager_result.status().error_code());
  }

  // Registration of standard key types works.
  auto status = SignatureConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  for (const auto& sign_key_type : sign_key_types) {
    auto sign_manager_result =
        Registry::get_key_manager<PublicKeySign>(sign_key_type);
    EXPECT_TRUE(sign_manager_result.ok()) << sign_manager_result.status();
    EXPECT_TRUE(sign_manager_result.ValueOrDie()->DoesSupport(sign_key_type));
  }

  for (const auto& verify_key_type : verify_key_types) {
    auto verify_manager_result =
        Registry::get_key_manager<PublicKeyVerify>(verify_key_type);
    EXPECT_TRUE(verify_manager_result.ok()) << verify_manager_result.status();
    EXPECT_TRUE(
        verify_manager_result.ValueOrDie()->DoesSupport(verify_key_type));
  }
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
                                  absl::make_unique<DummySignCatalogue>());
  EXPECT_TRUE(status.ok()) << status;
  status = SignatureConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
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
  primitive_set->set_primary(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("dummy"), key)
          .ValueOrDie());

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
  primitive_set->set_primary(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyPublicKeyVerify>("dummy"), key)
          .ValueOrDie());
  std::string prefix = CryptoFormat::get_output_prefix(key).ValueOrDie();
  std::string signature = DummyPublicKeySign("dummy").Sign("message").ValueOrDie();

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  ASSERT_TRUE(wrapped.ValueOrDie()
                  ->Verify(absl::StrCat(prefix, signature), "message")
                  .ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
