// Copyright 2020 Google LLC
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
#include "tink/prf/prf_config.h"

#include <list>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/prf/prf_set.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class PrfConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(PrfConfigTest, RegisterWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<Prf>(HmacPrfKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(PrfConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<Prf>(HmacPrfKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// FIPS-only mode tests
TEST_F(PrfConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(PrfConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(PrfKeyTemplates::HkdfSha256());
  non_fips_key_templates.push_back(PrfKeyTemplates::AesCmac());

  for (auto key_template : non_fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result.status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST_F(PrfConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(PrfConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(PrfKeyTemplates::HmacSha256());
  fips_key_templates.push_back(PrfKeyTemplates::HmacSha512());

  for (auto key_template : fips_key_templates) {
    auto new_keyset_handle_result = KeysetHandle::GenerateNew(key_template);
    EXPECT_THAT(new_keyset_handle_result, IsOk());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
