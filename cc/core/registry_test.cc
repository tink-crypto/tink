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

#include <thread>  // NOLINT(build/c++11)
#include <vector>

#include "cc/aead.h"
#include "cc/registry.h"
#include "cc/crypto_format.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/test_util.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "gtest/gtest.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using cloud::crypto::tink::test::DummyAead;
using google::cloud::crypto::tink::AesCtrHmacAeadKey;
using google::cloud::crypto::tink::AesGcmKey;
using google::cloud::crypto::tink::AesGcmKeyFormat;
using google::cloud::crypto::tink::KeyData;
using google::cloud::crypto::tink::Keyset;
using google::cloud::crypto::tink::KeyStatusType;
using google::cloud::crypto::tink::KeyTemplate;
using google::cloud::crypto::tink::OutputPrefixType;
using google::protobuf::Message;
using google::protobuf::StringPiece;
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

class TestAeadKeyManager : public KeyManager<Aead> {
 public:
  TestAeadKeyManager(const std::string& key_type) : key_type_(key_type) {
  }

  util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitive(const KeyData& key) const override {
    std::unique_ptr<Aead> aead(new DummyAead(key_type_));
    return std::move(aead);
  }

  util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitive(const Message& key) const override {
    return util::Status::UNKNOWN;
  }

  util::StatusOr<std::unique_ptr<google::protobuf::Message>> NewKey(
      const KeyTemplate& key_template) const override {
    return util::Status::UNKNOWN;
  }

  int get_version() const override {
    return 0;
  }

  const std::string& get_key_type() const override {
    return key_type_;
  }

 private:
  std::string key_type_;
};

void register_test_managers(Registry* registry,
                            const std::string& key_type_prefix,
                            int manager_count) {
  for (int i = 0; i < manager_count; i++) {
    std::string key_type = key_type_prefix + std::to_string(i);
    util::Status status = registry->RegisterKeyManager(
        key_type, new TestAeadKeyManager(key_type));
    EXPECT_TRUE(status.ok()) << status;
  }
}

void verify_test_managers(Registry* registry,
                          const std::string& key_type_prefix,
                          int manager_count) {
  for (int i = 0; i < manager_count; i++) {
    std::string key_type = key_type_prefix + std::to_string(i);
    auto manager_result = registry->get_key_manager<Aead>(key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    auto manager = manager_result.ValueOrDie();
    EXPECT_EQ(key_type, manager->get_key_type());
  }
}

TEST_F(RegistryTest, testConcurrentRegistration) {
  Registry registry;
  std::string key_type_prefix_a = "key_type_a_";
  std::string key_type_prefix_b = "key_type_b_";
  int count_a = 42;
  int count_b = 72;

  // Register some managers.
  std::thread register_a(register_test_managers, &registry,
                       key_type_prefix_a, count_a);
  std::thread register_b(register_test_managers, &registry,
                       key_type_prefix_b, count_b);
  register_a.join();
  register_b.join();

  // Check that the managers were registered.
  std::thread verify_a(verify_test_managers, &registry,
                       key_type_prefix_a, count_a);
  std::thread verify_b(verify_test_managers, &registry,
                       key_type_prefix_b, count_b);
  verify_a.join();
  verify_b.join();

  // Check that there are no extra managers.
  std::string key_type = key_type_prefix_a + std::to_string(count_a-1);
  auto manager_result = registry.get_key_manager<Aead>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_EQ(key_type, manager_result.ValueOrDie()->get_key_type());

  key_type = key_type_prefix_a + std::to_string(count_a);
  manager_result = registry.get_key_manager<Aead>(key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
}

TEST_F(RegistryTest, testBasic) {
  Registry registry;
  std::string key_type_1 = AesCtrHmacAeadKey::descriptor()->full_name();
  std::string key_type_2 = AesGcmKey::descriptor()->full_name();
  auto manager_result = registry.get_key_manager<Aead>(key_type_1);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND,
            manager_result.status().error_code());

  TestAeadKeyManager* null_key_manager = nullptr;
  util::Status status = registry.RegisterKeyManager(key_type_1,
                                                    null_key_manager);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code()) << status;

  status = registry.RegisterKeyManager(key_type_1,
      new TestAeadKeyManager(key_type_1));
  EXPECT_TRUE(status.ok()) << status;

  status = registry.RegisterKeyManager(key_type_1,
      new TestAeadKeyManager(key_type_1));
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code()) << status;

  status = registry.RegisterKeyManager(key_type_2,
      new TestAeadKeyManager(key_type_2));
  EXPECT_TRUE(status.ok()) << status;

  manager_result = registry.get_key_manager<Aead>(key_type_1);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  auto manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_1));
  EXPECT_FALSE(manager->DoesSupport(key_type_2));

  manager_result = registry.get_key_manager<Aead>(key_type_2);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_2));
  EXPECT_FALSE(manager->DoesSupport(key_type_1));
}

TEST_F(RegistryTest, testGettingPrimitives) {
  Registry registry;
  std::string key_type_1 = AesCtrHmacAeadKey::descriptor()->full_name();
  std::string key_type_2 = AesGcmKey::descriptor()->full_name();

  // Prepare keyset.
  Keyset::Key* key;
  Keyset keyset;

  uint32_t key_id_1 = 1234543;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_1);
  key->set_status(KeyStatusType::ENABLED);
  key->mutable_key_data()->set_type_url(key_type_1);

  uint32_t key_id_2 = 726329;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_2);
  key->set_status(KeyStatusType::DISABLED);
  key->mutable_key_data()->set_type_url(key_type_2);

  uint32_t key_id_3 = 7213743;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::LEGACY);
  key->set_key_id(key_id_3);
  key->set_status(KeyStatusType::ENABLED);
  key->mutable_key_data()->set_type_url(key_type_2);

  uint32_t key_id_4 = 6268492;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::RAW);
  key->set_key_id(key_id_4);
  key->set_status(KeyStatusType::ENABLED);
  key->mutable_key_data()->set_type_url(key_type_1);

  uint32_t key_id_5 = 42;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::RAW);
  key->set_key_id(key_id_5);
  key->set_status(KeyStatusType::ENABLED);
  key->mutable_key_data()->set_type_url(key_type_2);

  keyset.set_primary_key_id(key_id_3);

  // Register key managers.
  util::Status status;
  status = registry.RegisterKeyManager(key_type_1,
                                       new TestAeadKeyManager(key_type_1));
  EXPECT_TRUE(status.ok()) << status;
  status = registry.RegisterKeyManager(key_type_2,
                                       new TestAeadKeyManager(key_type_2));
  EXPECT_TRUE(status.ok()) << status;

  // Get and use primitives.
  std::string plaintext = "some data";
  std::string aad = "aad";

  // Key #1.
  {
    auto result = registry.GetPrimitive<Aead>(keyset.key(0).key_data());
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead = std::move(result.ValueOrDie());
    EXPECT_EQ(plaintext + key_type_1,
              aead->Encrypt(plaintext, aad).ValueOrDie());
  }

  // Key #3.
  {
    auto result = registry.GetPrimitive<Aead>(keyset.key(2).key_data());
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead = std::move(result.ValueOrDie());
    EXPECT_EQ(plaintext + key_type_2,
              aead->Encrypt(plaintext, aad).ValueOrDie());
  }

  // Keyset without custom key manager.
  {
    auto result = registry.GetPrimitives<Aead>(keyset, nullptr);
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead_set = std::move(result.ValueOrDie());

    // Check primary.
    EXPECT_FALSE(aead_set->get_primary() == nullptr);
    EXPECT_EQ(CryptoFormat::get_output_prefix(keyset.key(2)).ValueOrDie(),
              aead_set->get_primary()->get_identifier());

    // Check raw.
    auto raw = aead_set->get_raw_primitives().ValueOrDie();
    EXPECT_EQ(2, raw->size());
    EXPECT_EQ(plaintext + key_type_1,
              raw->at(0).get_primitive().Encrypt(plaintext, aad).ValueOrDie());
    EXPECT_EQ(plaintext + key_type_2,
              raw->at(1).get_primitive().Encrypt(plaintext, aad).ValueOrDie());

    // Check Tink.
    auto tink = aead_set->get_primitives(CryptoFormat::get_output_prefix(
        keyset.key(0)).ValueOrDie()).ValueOrDie();
    EXPECT_EQ(1, tink->size());
    EXPECT_EQ(plaintext + key_type_1,
              tink->at(0).get_primitive().Encrypt(plaintext, aad).ValueOrDie());

    // Check DISABLED.
    auto disabled = aead_set->get_primitives(
        CryptoFormat::get_output_prefix(keyset.key(1)).ValueOrDie());
    EXPECT_FALSE(disabled.ok());
    EXPECT_EQ(util::error::NOT_FOUND, disabled.status().error_code());
  }

  // TODO(przydatek): add test: Keyset with custom key manager.
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
