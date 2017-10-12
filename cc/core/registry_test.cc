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

#include "absl/strings/string_view.h"
#include "cc/aead.h"
#include "cc/catalogue.h"
#include "cc/registry.h"
#include "cc/crypto_format.h"
#include "cc/aead/aead_catalogue.h"
#include "cc/aead/aes_gcm_key_manager.h"
#include "cc/util/ptr_util.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddLegacyKey;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using crypto::tink::test::DummyAead;
using crypto::tink::test::GetKeysetHandle;
using google::crypto::tink::AesCtrHmacAeadKey;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using google::protobuf::Message;
using crypto::tink::util::Status;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {
namespace {

class RegistryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }
  void TearDown() override {
  }
};

class TestKeyFactory : public KeyFactory {
 public:
  TestKeyFactory(const std::string& key_type) : key_type_(key_type) {
  }

  util::StatusOr<std::unique_ptr<google::protobuf::Message>> NewKey(
      const Message& key_format) const override {
    return util::Status::UNKNOWN;
  }

  util::StatusOr<std::unique_ptr<google::protobuf::Message>> NewKey(
      absl::string_view serialized_key_format) const override {
    return util::Status::UNKNOWN;
  }

  util::StatusOr<std::unique_ptr<KeyData>> NewKeyData(
      absl::string_view serialized_key_format) const override {
    auto key_data = util::make_unique<KeyData>();
    key_data->set_type_url(key_type_);
    key_data->set_value(std::string(serialized_key_format));
    return std::move(key_data);
  }

 private:
  std::string key_type_;
};

class TestAeadKeyManager : public KeyManager<Aead> {
 public:
  TestAeadKeyManager(const std::string& key_type)
      : key_type_(key_type), key_factory_(key_type) {
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


  uint32_t get_version() const override {
    return 0;
  }

  const std::string& get_key_type() const override {
    return key_type_;
  }

  const KeyFactory& get_key_factory() const override {
    return key_factory_;
  }

 private:
  std::string key_type_;
  TestKeyFactory key_factory_;
};


class TestAeadCatalogue : public Catalogue<Aead> {
 public:
  TestAeadCatalogue() {}

  util::StatusOr<std::unique_ptr<KeyManager<Aead>>>
      GetKeyManager(const std::string& type_url,
                    const std::string& primitive_name,
                    uint32_t min_version) const override {
    return util::Status(util::error::UNIMPLEMENTED,
                        "This is a test catalogue.");
  }
};

void register_test_managers(const std::string& key_type_prefix,
                            int manager_count) {
  for (int i = 0; i < manager_count; i++) {
    std::string key_type = key_type_prefix + std::to_string(i);
    util::Status status = Registry::RegisterKeyManager(
        key_type, new TestAeadKeyManager(key_type));
    EXPECT_TRUE(status.ok()) << status;
  }
}

void verify_test_managers(const std::string& key_type_prefix,
                          int manager_count) {
  for (int i = 0; i < manager_count; i++) {
    std::string key_type = key_type_prefix + std::to_string(i);
    auto manager_result = Registry::get_key_manager<Aead>(key_type);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    auto manager = manager_result.ValueOrDie();
    EXPECT_EQ(key_type, manager->get_key_type());
  }
}

TEST_F(RegistryTest, testConcurrentRegistration) {
  std::string key_type_prefix_a = "key_type_a_";
  std::string key_type_prefix_b = "key_type_b_";
  int count_a = 42;
  int count_b = 72;

  // Register some managers.
  std::thread register_a(register_test_managers,
                         key_type_prefix_a, count_a);
  std::thread register_b(register_test_managers,
                         key_type_prefix_b, count_b);
  register_a.join();
  register_b.join();

  // Check that the managers were registered.
  std::thread verify_a(verify_test_managers,
                       key_type_prefix_a, count_a);
  std::thread verify_b(verify_test_managers,
                       key_type_prefix_b, count_b);
  verify_a.join();
  verify_b.join();

  // Check that there are no extra managers.
  std::string key_type = key_type_prefix_a + std::to_string(count_a-1);
  auto manager_result = Registry::get_key_manager<Aead>(key_type);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  EXPECT_EQ(key_type, manager_result.ValueOrDie()->get_key_type());

  key_type = key_type_prefix_a + std::to_string(count_a);
  manager_result = Registry::get_key_manager<Aead>(key_type);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
}

TEST_F(RegistryTest, testBasic) {
  std::string key_type_1 = AesCtrHmacAeadKey::descriptor()->full_name();
  std::string key_type_2 = AesGcmKey::descriptor()->full_name();
  auto manager_result = Registry::get_key_manager<Aead>(key_type_1);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND,
            manager_result.status().error_code());

  auto status = Registry::RegisterKeyManager(key_type_1,
      new TestAeadKeyManager(key_type_1));
  EXPECT_TRUE(status.ok()) << status;

  status = Registry::RegisterKeyManager(key_type_2,
      new TestAeadKeyManager(key_type_2));
  EXPECT_TRUE(status.ok()) << status;

  manager_result = Registry::get_key_manager<Aead>(key_type_1);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  auto manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_1));
  EXPECT_FALSE(manager->DoesSupport(key_type_2));

  manager_result = Registry::get_key_manager<Aead>(key_type_2);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_2));
  EXPECT_FALSE(manager->DoesSupport(key_type_1));
}

TEST_F(RegistryTest, testRegisterKeyManager) {
  std::string key_type_1 = AesGcmKeyManager::kKeyType;

  TestAeadKeyManager* null_key_manager = nullptr;
  auto status = Registry::RegisterKeyManager(key_type_1, null_key_manager);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code()) << status;

  // Register a key manager.
  status = Registry::RegisterKeyManager(key_type_1,
      new TestAeadKeyManager(key_type_1));
  EXPECT_TRUE(status.ok()) << status;

  // Register the same key manager again, it should work (idempotence).
  EXPECT_TRUE(status.ok()) << status;

  // Try overriding a key manager.
  status = Registry::RegisterKeyManager(key_type_1, new AesGcmKeyManager());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code()) << status;

  // Check the key manager is still registered.
  auto manager_result = Registry::get_key_manager<Aead>(key_type_1);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  auto manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_1));
}

TEST_F(RegistryTest, testAddCatalogue) {
  std::string catalogue_name = "SomeCatalogue";

  TestAeadCatalogue* null_catalogue = nullptr;
  auto status = Registry::AddCatalogue(catalogue_name, null_catalogue);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code()) << status;

  // Add a catalogue.
  status = Registry::AddCatalogue(catalogue_name, new TestAeadCatalogue());
  EXPECT_TRUE(status.ok()) << status;

  // Add the same catalogue again, it should work (idempotence).
  status = Registry::AddCatalogue(catalogue_name, new TestAeadCatalogue());
  EXPECT_TRUE(status.ok()) << status;

  // Try overriding a catalogue.
  status = Registry::AddCatalogue(catalogue_name, new AeadCatalogue());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code()) << status;

  // Check the catalogue is still present.
  auto catalogue_result = Registry::get_catalogue<Aead>(catalogue_name);
  EXPECT_TRUE(catalogue_result.ok()) << catalogue_result.status();
  auto catalogue = catalogue_result.ValueOrDie();
  auto manager_result = catalogue->GetKeyManager("some type_url", "Aead", 0);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::UNIMPLEMENTED, manager_result.status().error_code())
      << manager_result.status();  // TestAeadCatalogue return UNIMPLEMENTED.
}

TEST_F(RegistryTest, testGettingPrimitives) {
  std::string key_type_1 = AesCtrHmacAeadKey::descriptor()->full_name();
  std::string key_type_2 = AesGcmKey::descriptor()->full_name();
  AesCtrHmacAeadKey dummy_key_1;
  AesGcmKey dummy_key_2;

  // Prepare keyset.
  Keyset keyset;

  uint32_t key_id_1 = 1234543;
  AddTinkKey(key_type_1, key_id_1, dummy_key_1, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  AddTinkKey(key_type_2, key_id_2, dummy_key_2, KeyStatusType::DISABLED,
             KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  AddLegacyKey(key_type_2, key_id_3, dummy_key_2, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_4 = 6268492;
  AddRawKey(key_type_1, key_id_4, dummy_key_1, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_5 = 42;
  AddRawKey(key_type_2, key_id_5, dummy_key_2, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Register key managers.
  util::Status status;
  status = Registry::RegisterKeyManager(key_type_1,
                                        new TestAeadKeyManager(key_type_1));
  EXPECT_TRUE(status.ok()) << status;
  status = Registry::RegisterKeyManager(key_type_2,
                                        new TestAeadKeyManager(key_type_2));
  EXPECT_TRUE(status.ok()) << status;

  // Get and use primitives.
  std::string plaintext = "some data";
  std::string aad = "aad";

  // Key #1.
  {
    auto result = Registry::GetPrimitive<Aead>(keyset.key(0).key_data());
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead = std::move(result.ValueOrDie());
    EXPECT_EQ(plaintext + key_type_1,
              aead->Encrypt(plaintext, aad).ValueOrDie());
  }

  // Key #3.
  {
    auto result = Registry::GetPrimitive<Aead>(keyset.key(2).key_data());
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead = std::move(result.ValueOrDie());
    EXPECT_EQ(plaintext + key_type_2,
              aead->Encrypt(plaintext, aad).ValueOrDie());
  }

  // Keyset without custom key manager.
  {
    auto result = Registry::GetPrimitives<Aead>(*GetKeysetHandle(keyset),
                                                nullptr);
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

TEST_F(RegistryTest, testNewKeyData) {
  std::string key_type_1 = AesCtrHmacAeadKey::descriptor()->full_name();
  std::string key_type_2 = AesGcmKey::descriptor()->full_name();
  std::string key_type_3 = "yet/another/keytype";

  // Register key managers.
  util::Status status;
  status = Registry::RegisterKeyManager(key_type_1,
                                        new TestAeadKeyManager(key_type_1));
  EXPECT_TRUE(status.ok()) << status;
  status = Registry::RegisterKeyManager(key_type_2,
                                        new TestAeadKeyManager(key_type_2));
  EXPECT_TRUE(status.ok()) << status;
  status = Registry::RegisterKeyManager(key_type_3,
                                        new TestAeadKeyManager(key_type_3),
                                        /* new_key_allowed= */ false);
  EXPECT_TRUE(status.ok()) << status;

  {  // A supported key type.
    KeyTemplate key_template;
    key_template.set_type_url(key_type_1);
    key_template.set_value("test value 42");
    auto new_key_data_result = Registry::NewKeyData(key_template);
    EXPECT_TRUE(new_key_data_result.ok()) << new_key_data_result.status();
    EXPECT_EQ(key_type_1, new_key_data_result.ValueOrDie()->type_url());
    EXPECT_EQ(key_template.value(), new_key_data_result.ValueOrDie()->value());
  }

  {  // Another supported key type.
    KeyTemplate key_template;
    key_template.set_type_url(key_type_2);
    key_template.set_value("yet another test value 42");
    auto new_key_data_result = Registry::NewKeyData(key_template);
    EXPECT_TRUE(new_key_data_result.ok()) << new_key_data_result.status();
    EXPECT_EQ(key_type_2, new_key_data_result.ValueOrDie()->type_url());
    EXPECT_EQ(key_template.value(), new_key_data_result.ValueOrDie()->value());
  }

  {  // A key type that does not allow NewKey-operations.
    KeyTemplate key_template;
    key_template.set_type_url(key_type_3);
    key_template.set_value("some other value 72");
    auto new_key_data_result = Registry::NewKeyData(key_template);
    EXPECT_FALSE(new_key_data_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              new_key_data_result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, key_type_3,
                        new_key_data_result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "does not allow",
                        new_key_data_result.status().error_message());
  }

  {  // A key type that is not supported.
    KeyTemplate key_template;
    std::string bad_type_url = "some key type that is not supported";
    key_template.set_type_url(bad_type_url);
    key_template.set_value("some totally other value 42");
    auto new_key_data_result = Registry::NewKeyData(key_template);
    EXPECT_FALSE(new_key_data_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND,
              new_key_data_result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, bad_type_url,
                        new_key_data_result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
