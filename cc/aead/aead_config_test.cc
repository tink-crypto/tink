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
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeyTemplate;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::Test;

class AeadConfigTest : public Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(AeadConfigTest, RegisterWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
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

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(keyset_handle.status(), IsOk());
  StatusOr<std::unique_ptr<Aead>> aead = (*keyset_handle)->GetPrimitive<Aead>();
  ASSERT_THAT(aead.status(), IsOk());
  ASSERT_THAT(*aead, Not(IsNull()));
}

// FIPS-only mode tests
TEST_F(AeadConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  ASSERT_THAT(AeadConfig::Register(), IsOk());

  std::list<KeyTemplate> non_fips_key_templates = {
      AeadKeyTemplates::Aes128Eax(),         AeadKeyTemplates::Aes256Eax(),
      AeadKeyTemplates::Aes128GcmSiv(),      AeadKeyTemplates::Aes256GcmSiv(),
      AeadKeyTemplates::XChaCha20Poly1305(),
  };

  for (auto key_template : non_fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result.status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST_F(AeadConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(AeadConfig::Register(), IsOk());

  std::list<KeyTemplate> fips_key_templates = {
      AeadKeyTemplates::Aes128Gcm(),
      AeadKeyTemplates::Aes256Gcm(),
      AeadKeyTemplates::Aes128CtrHmacSha256(),
      AeadKeyTemplates::Aes256CtrHmacSha256(),
  };

  for (auto key_template : fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result, IsOk());
  }
}

TEST_F(AeadConfigTest, RegisterFailsIfBoringCryptoNotAvailable) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Only supported in FIPS-only mode with BoringCrypto not available.";
  }

  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(AeadConfig::Register(), StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
