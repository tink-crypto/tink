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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/config.h"
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
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  EciesAeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  EciesAeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  HybridConfig::Register();
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
  ASSERT_TRUE(HybridConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridEncrypt>>();
  primitive_set->set_primary(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyHybridEncrypt>("dummy"), key)
          .ValueOrDie());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto encryption_result = wrapped.ValueOrDie()->Encrypt("secret", "");
  ASSERT_TRUE(encryption_result.ok());

  std::string prefix = CryptoFormat::get_output_prefix(key).ValueOrDie();
  EXPECT_EQ(
      encryption_result.ValueOrDie(),
      absl::StrCat(
          prefix,
          DummyHybridEncrypt("dummy").Encrypt("secret", "").ValueOrDie()));
}

// Tests that the HybridDecryptWrapper has been properly registered and we
// can wrap primitives.
TEST_F(HybridConfigTest, DecryptWrapperRegistered) {
  ASSERT_TRUE(HybridConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridDecrypt>>();
  primitive_set->set_primary(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyHybridDecrypt>("dummy"), key)
          .ValueOrDie());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();

  std::string prefix = CryptoFormat::get_output_prefix(key).ValueOrDie();
  std::string encryption =
      DummyHybridEncrypt("dummy").Encrypt("secret", "").ValueOrDie();

  ASSERT_EQ(wrapped.ValueOrDie()
                ->Decrypt(absl::StrCat(prefix, encryption), "")
                .ValueOrDie(),
            "secret");
}

}  // namespace
}  // namespace tink
}  // namespace crypto
