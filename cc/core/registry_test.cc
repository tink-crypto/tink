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

#include <vector>

#include "cc/aead.h"
#include "cc/registry.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/message_lite.h"
#include "gtest/gtest.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"


using google::cloud::crypto::tink::AesCtrHmacAeadKey;
using google::cloud::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::cloud::crypto::tink::AesGcmKey;
using google::cloud::crypto::tink::AesGcmKeyFormat;
using google::cloud::crypto::tink::Keyset;
using google::protobuf::MessageLite;
using util::Status;

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class RegistryTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

template <class K, class F>
class TestAeadKeyManager :
      public KeyManager<Aead> {
 public:
  TestAeadKeyManager(const std::string& key_type) {
    key_types_.push_back(key_type);
  }

  util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitive(const MessageLite& key) const override {
    return util::Status::UNKNOWN;
  }

  util::Status NewKey(const MessageLite& key_format, MessageLite* key) const override {
    return util::Status::UNKNOWN;
  }

  const std::vector<std::string>&  get_supported_key_types() const override {
    return key_types_;
  }
 private:
  std::vector<std::string> key_types_;
};

TEST_F(RegistryTest, testBasic) {
  Registry& registry = Registry::get_default_registry();
  std::string key_type_1 = AesCtrHmacAeadKey::descriptor()->full_name();
  std::string key_type_2 = AesGcmKey::descriptor()->full_name();
  auto manager_result = registry.get_manager<Aead>(key_type_1);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND,
            manager_result.status().error_code());

  registry.RegisterKeyManager(key_type_1,
      new TestAeadKeyManager<AesCtrHmacAeadKey,
                             AesCtrHmacAeadKeyFormat>(key_type_1));
  registry.RegisterKeyManager(key_type_2,
      new TestAeadKeyManager<AesGcmKey,
                             AesGcmKeyFormat>(key_type_2));

  manager_result = registry.get_manager<Aead>(key_type_1);
  EXPECT_TRUE(manager_result.ok());
  auto manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_1));
  EXPECT_FALSE(manager->DoesSupport(key_type_2));

  manager_result = registry.get_manager<Aead>(key_type_2);
  EXPECT_TRUE(manager_result.ok());
  manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_2));
  EXPECT_FALSE(manager->DoesSupport(key_type_1));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
