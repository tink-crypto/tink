// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_config.h"

#include <list>
#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/config.h"
#include "tink/config/tink_fips.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyStreamingAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class StreamingAeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(StreamingAeadConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesGcmHkdfStreamingKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesCtrHmacStreamingKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  EXPECT_THAT(StreamingAeadConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesGcmHkdfStreamingKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesCtrHmacStreamingKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the StreamingAeadWrapper has been properly registered
// and we can wrap primitives.
TEST_F(StreamingAeadConfigTest, WrappersRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(StreamingAeadConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<StreamingAead>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyStreamingAead>("dummy"),
                             key_info)
              .ValueOrDie()),
      IsOk());

  auto primitive_result = Registry::Wrap(std::move(primitive_set));
  ASSERT_TRUE(primitive_result.ok()) << primitive_result.status();
}

// FIPS-only mode tests
TEST_F(StreamingAeadConfigTest, RegisterNonFipsTemplates) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  EXPECT_THAT(StreamingAeadConfig::Register(), IsOk());

  // Check that we can not retrieve non-FIPS keyset handle
  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes256GcmHkdf1MB());
  non_fips_key_templates.push_back(
      StreamingAeadKeyTemplates::Aes256GcmHkdf4KB());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(key_template).status(),
                StatusIs(util::error::NOT_FOUND));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
