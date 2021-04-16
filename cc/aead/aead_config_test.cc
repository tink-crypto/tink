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

#include "tink/aead/aead_config.h"

#include <list>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "openssl/crypto.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

class AeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(AeadConfigTest, RegisterWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(AeadConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the AeadWrapper has been properly registered and we can wrap
// primitives.
TEST_F(AeadConfigTest, WrappersRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(AeadConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<Aead>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyAead>("dummy"), key_info)
              .ValueOrDie()),
      IsOk());

  auto primitive_result = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(primitive_result.ok()) << primitive_result.status();
  auto encryption_result = primitive_result.ValueOrDie()->Encrypt("secret", "");
  ASSERT_TRUE(encryption_result.ok());

  auto decryption_result =
      DummyAead("dummy").Decrypt(encryption_result.ValueOrDie(), "");
  ASSERT_TRUE(decryption_result.status().ok());
  EXPECT_THAT(decryption_result.ValueOrDie(), Eq("secret"));

  decryption_result =
      DummyAead("dummy").Decrypt(encryption_result.ValueOrDie(), "wrog");
  EXPECT_FALSE(decryption_result.status().ok());
}

// FIPS-only mode tests
TEST_F(AeadConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(AeadConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(AeadKeyTemplates::Aes128Eax());
  non_fips_key_templates.push_back(AeadKeyTemplates::Aes256Eax());
  non_fips_key_templates.push_back(AeadKeyTemplates::Aes128GcmSiv());
  non_fips_key_templates.push_back(AeadKeyTemplates::Aes256GcmSiv());
  non_fips_key_templates.push_back(AeadKeyTemplates::XChaCha20Poly1305());

  for (auto key_template : non_fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result.status(),
                StatusIs(util::error::NOT_FOUND));
  }
}

TEST_F(AeadConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(AeadConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(AeadKeyTemplates::Aes128Gcm());
  fips_key_templates.push_back(AeadKeyTemplates::Aes256Gcm());
  fips_key_templates.push_back(AeadKeyTemplates::Aes128CtrHmacSha256());
  fips_key_templates.push_back(AeadKeyTemplates::Aes256CtrHmacSha256());

  for (auto key_template : fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result.status(), IsOk());
  }
}

TEST_F(AeadConfigTest, RegisterFailsIfBoringCryptoNotAvailable) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Only supported in FIPS-only mode with BoringCrypto not available.";
  }

  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(AeadConfig::Register(), StatusIs(util::error::INTERNAL));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
