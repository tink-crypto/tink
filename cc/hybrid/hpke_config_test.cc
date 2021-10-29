// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/hpke_config.h"

#include <list>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config/tink_fips.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
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

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class HpkeConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(HpkeConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  internal::HpkePrivateKeyManager().get_key_type()).status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  internal::HpkePublicKeyManager().get_key_type()).status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(RegisterHpke(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  internal::HpkePrivateKeyManager().get_key_type()).status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  internal::HpkePublicKeyManager().get_key_type()).status(),
              IsOk());
}

// FIPS-only mode tests
TEST_F(HpkeConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(RegisterHpke(), IsOk());

  // Check that we can not retrieve non-FIPS keyset handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm());
  non_fips_key_templates.push_back(
      HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
