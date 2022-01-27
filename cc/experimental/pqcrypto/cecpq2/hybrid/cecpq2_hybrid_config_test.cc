// Copyright 2021 Google LLC
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

#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_hybrid_config.h"

#include <list>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config/tink_fips.h"
#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_private_key_manager.h"
#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_public_key_manager.h"
#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_hybrid_key_templates.h"
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

class Cecpq2HybridConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(Cecpq2HybridConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  Cecpq2AeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  Cecpq2AeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Cecpq2HybridConfigRegister(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  Cecpq2AeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  Cecpq2AeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the HybridEncrypt wrapper has been properly registered and we
// can wrap primitives
TEST_F(Cecpq2HybridConfigTest, EncryptWrapperRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(Cecpq2HybridConfigRegister().ok());

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
              .ValueOrDie()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_THAT(wrapped.status(), IsOk());
  auto encryption_result = wrapped.ValueOrDie()->Encrypt("secret", "");
  ASSERT_THAT(encryption_result.status(), IsOk());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).ValueOrDie();
  EXPECT_EQ(
      encryption_result.ValueOrDie(),
      absl::StrCat(
          prefix,
          DummyHybridEncrypt("dummy").Encrypt("secret", "").ValueOrDie()));
}

// Tests that the HybridDecrypt wrapper has been properly registered and we
// can wrap primitives
TEST_F(Cecpq2HybridConfigTest, DecryptWrapperRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(Cecpq2HybridConfigRegister().ok());

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
              .ValueOrDie()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_THAT(wrapped.status(), IsOk());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).ValueOrDie();
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
