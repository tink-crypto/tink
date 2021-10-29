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

#include "tink/mac/mac_config.h"

#include <list>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyMac;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class MacConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }
};

TEST_F(MacConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(
      Registry::get_key_manager<Mac>(HmacKeyManager().get_key_type()).status(),
      StatusIs(absl::StatusCode::kNotFound));
  ASSERT_THAT(MacConfig::Register(), IsOk());
  EXPECT_THAT(
      Registry::get_key_manager<Mac>(HmacKeyManager().get_key_type()).status(),
      IsOk());
}

// Tests that the MacWrapper has been properly registered and we can wrap
// primitives.
TEST_F(MacConfigTest, WrappersRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(MacConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<Mac>>();
  ASSERT_TRUE(
      primitive_set
          ->set_primary(
              primitive_set
                  ->AddPrimitive(absl::make_unique<DummyMac>("dummy"), key_info)
                  .ValueOrDie())
          .ok());

  auto primitive_result = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(primitive_result.ok()) << primitive_result.status();
  auto mac_result =
      primitive_result.ValueOrDie()->ComputeMac("verified text");
  ASSERT_TRUE(mac_result.ok());

  EXPECT_TRUE(DummyMac("dummy")
                  .VerifyMac(mac_result.ValueOrDie(), "verified text")
                  .ok());
  EXPECT_FALSE(
      DummyMac("dummy").VerifyMac(mac_result.ValueOrDie(), "faked text").ok());
}

// FIPS-only mode tests
TEST_F(MacConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(MacConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(MacKeyTemplates::AesCmac());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST_F(MacConfigTest, RegisterFipsValidTemplates) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(MacConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(MacKeyTemplates::HmacSha256());
  fips_key_templates.push_back(MacKeyTemplates::HmacSha256HalfSizeTag());
  fips_key_templates.push_back(MacKeyTemplates::HmacSha512());
  fips_key_templates.push_back(MacKeyTemplates::HmacSha512HalfSizeTag());

  for (auto key_template : fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(), IsOk());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
