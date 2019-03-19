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
#include "absl/memory/memory.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "tink/catalogue.h"
#include "tink/config.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "gtest/gtest.h"
#include "tink/util/test_util.h"


namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyStreamingAead;
using ::testing::Eq;

class DummyStreamingAeadCatalogue : public Catalogue<StreamingAead> {
 public:
  DummyStreamingAeadCatalogue() {}

  crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<StreamingAead>>>
  GetKeyManager(
      const std::string& type_url,
      const std::string& primitive_name,
      uint32_t min_version) const override {
    return util::Status::UNKNOWN;
  }
};

class StreamingAeadConfigTest : public ::testing::Test {
 protected:
  void SetUp() override { Registry::Reset(); }
};

TEST_F(StreamingAeadConfigTest, testBasic) {
  std::string aes_gcm_hkdf_streaming_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
  auto& config = StreamingAeadConfig::Latest();

  EXPECT_EQ(1, StreamingAeadConfig::Latest().entry_size());

  EXPECT_EQ("TinkStreamingAead", config.entry(0).catalogue_name());
  EXPECT_EQ("StreamingAead", config.entry(0).primitive_name());
  EXPECT_EQ(aes_gcm_hkdf_streaming_key_type, config.entry(0).type_url());
  EXPECT_EQ(true, config.entry(0).new_key_allowed());
  EXPECT_EQ(0, config.entry(0).key_manager_version());

  // No key manager before registration.
  auto manager_result =
      Registry::get_key_manager<StreamingAead>(aes_gcm_hkdf_streaming_key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());

  // Registration of standard key types works.
  auto status = StreamingAeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result =
      Registry::get_key_manager<StreamingAead>(aes_gcm_hkdf_streaming_key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(
      aes_gcm_hkdf_streaming_key_type));
}

TEST_F(StreamingAeadConfigTest, testRegister) {
  std::string key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  // Try on empty registry.
  auto status = Config::Register(StreamingAeadConfig::Latest());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::NOT_FOUND, status.error_code());
  auto manager_result = Registry::get_key_manager<StreamingAead>(key_type);
  EXPECT_FALSE(manager_result.ok());

  // Register and try again.
  status = StreamingAeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;
  manager_result = Registry::get_key_manager<StreamingAead>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();

  // Try Register() again, should succeed (idempotence).
  status = StreamingAeadConfig::Register();
  EXPECT_TRUE(status.ok()) << status;

  // Reset the registry, and try overriding a catalogue with a different one.
  Registry::Reset();
  status = Registry::AddCatalogue(
      "TinkStreamingAead", absl::make_unique<DummyStreamingAeadCatalogue>());
  EXPECT_TRUE(status.ok()) << status;
  status = StreamingAeadConfig::Register();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code());
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
