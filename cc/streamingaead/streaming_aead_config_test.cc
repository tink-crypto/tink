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

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/config.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/streaming_aead.h"
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
using ::testing::Eq;

class StreamingAeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(StreamingAeadConfigTest, Basic) {
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesGcmHkdfStreamingKeyManager().get_key_type())
                  .status(),
              StatusIs(util::error::NOT_FOUND));
  StreamingAeadConfig::Register();
  EXPECT_THAT(Registry::get_key_manager<StreamingAead>(
                  AesGcmHkdfStreamingKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the StreamingAeadWrapper has been properly registered
// and we can wrap primitives.
TEST_F(StreamingAeadConfigTest, WrappersRegistered) {
  ASSERT_TRUE(StreamingAeadConfig::Register().ok());

  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
  auto primitive_set = absl::make_unique<PrimitiveSet<StreamingAead>>();
  primitive_set->set_primary(primitive_set->AddPrimitive(
      absl::make_unique<DummyStreamingAead>("dummy"), key).ValueOrDie());

  auto primitive_result = Registry::Wrap(std::move(primitive_set));
  ASSERT_TRUE(primitive_result.ok()) << primitive_result.status();
}

}  // namespace
}  // namespace tink
}  // namespace crypto
