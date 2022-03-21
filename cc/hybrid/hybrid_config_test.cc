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

#include "tink/hybrid/hybrid_config.h"

#include <list>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyHybridDecrypt;
using ::crypto::tink::test::DummyHybridEncrypt;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class HybridConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(HybridConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  EciesAeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  EciesAeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(HybridConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  EciesAeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  EciesAeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the HybridEncryptWrapper has been properly registered and we
// can wrap primitives.
TEST_F(HybridConfigTest, EncryptWrapperRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(HybridConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridEncrypt>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyHybridEncrypt>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto encryption_result = wrapped.value()->Encrypt("secret", "");
  ASSERT_TRUE(encryption_result.ok());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  EXPECT_EQ(
      encryption_result.value(),
      absl::StrCat(prefix,
                   DummyHybridEncrypt("dummy").Encrypt("secret", "").value()));
}

// Tests that the HybridDecryptWrapper has been properly registered and we
// can wrap primitives.
TEST_F(HybridConfigTest, DecryptWrapperRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(HybridConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridDecrypt>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyHybridDecrypt>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  std::string encryption =
      DummyHybridEncrypt("dummy").Encrypt("secret", "").value();

  ASSERT_EQ(wrapped.ValueOrDie()
                ->Decrypt(absl::StrCat(prefix, encryption), "")
                .value(),
            "secret");
}

// FIPS-only mode tests
TEST_F(HybridConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(HybridConfig::Register(), IsOk());

  // Check that we can not retrieve non-FIPS keyset handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(
      HybridKeyTemplates::
          EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::
          EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
