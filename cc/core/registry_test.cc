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

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_catalogue.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/catalogue.h"
#include "tink/crypto_format.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/keyset_manager.h"
#include "tink/registry.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using crypto::tink::test::AddLegacyKey;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using crypto::tink::test::DummyAead;
using crypto::tink::util::Status;
using google::crypto::tink::AesCtrHmacAeadKey;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;
using portable_proto::MessageLite;

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

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> NewKey(
      const MessageLite& key_format) const override {
    return util::Status::UNKNOWN;
  }

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> NewKey(
      absl::string_view serialized_key_format) const override {
    return util::Status::UNKNOWN;
  }

  util::StatusOr<std::unique_ptr<KeyData>> NewKeyData(
      absl::string_view serialized_key_format) const override {
    auto key_data = absl::make_unique<KeyData>();
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
  GetPrimitive(const MessageLite& key) const override {
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

template <typename P>
class TestWrapper : public PrimitiveWrapper<P> {
 public:
  TestWrapper() {}
  crypto::tink::util::StatusOr<std::unique_ptr<P>> Wrap(
      std::unique_ptr<PrimitiveSet<P>> primitive_set) const override {
    return util::Status(util::error::UNIMPLEMENTED, "This is a test wrapper.");
  }
};

void register_test_managers(const std::string& key_type_prefix,
                            int manager_count) {
  for (int i = 0; i < manager_count; i++) {
    std::string key_type = key_type_prefix + std::to_string(i);
    util::Status status = Registry::RegisterKeyManager(
        new TestAeadKeyManager(key_type));
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

TEST_F(RegistryTest, testRegisterKeyManagerMoreRestrictiveNewKeyAllowed) {
  std::string key_type = "some_key_type";
  KeyTemplate key_template;
  key_template.set_type_url(key_type);

  // Register the key manager with new_key_allowed == true and verify that
  // new key data can be created.
  util::Status status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type),
      /* new_key_allowed= */ true);
  EXPECT_TRUE(status.ok()) << status;

  auto result_before = Registry::NewKeyData(key_template);
  EXPECT_TRUE(result_before.ok()) << result_before.status();

  // Re-register the key manager with new_key_allowed == false and check the
  // restriction (i.e. new key data cannot be created).
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type),
      /* new_key_allowed= */ false);
  EXPECT_TRUE(status.ok()) << status;

  auto result_after = Registry::NewKeyData(key_template);
  EXPECT_FALSE(result_after.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result_after.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, key_type,
                      result_after.status().error_message());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "does not allow",
                      result_after.status().error_message());
}

TEST_F(RegistryTest, testRegisterKeyManagerLessRestrictiveNewKeyAllowed) {
  std::string key_type = "some_key_type";
  KeyTemplate key_template;
  key_template.set_type_url(key_type);

  // Register the key manager with new_key_allowed == false.
  util::Status status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type),
      /* new_key_allowed= */ false);
  EXPECT_TRUE(status.ok()) << status;

  // Verify that re-registering the key manager with new_key_allowed == true is
  // not possible and that the restriction still holds after that operation
  // (i.e. new key data cannot be created).
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type),
      /* new_key_allowed= */ true);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code()) << status;
  EXPECT_PRED_FORMAT2(testing::IsSubstring, key_type,
                      status.error_message()) << status;
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "forbidden new key operation" ,
                      status.error_message()) << status;

  auto result_after = Registry::NewKeyData(key_template);
  EXPECT_FALSE(result_after.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result_after.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, key_type,
                      result_after.status().error_message());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "does not allow",
                      result_after.status().error_message());
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
  std::string key_type_1 = "google.crypto.tink.AesCtrHmacAeadKey";
  std::string key_type_2 = "google.crypto.tink.AesGcmKey";
  auto manager_result = Registry::get_key_manager<Aead>(key_type_1);
  EXPECT_FALSE(manager_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND,
            manager_result.status().error_code());

  auto status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_1), true);


  EXPECT_TRUE(status.ok()) << status;

  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_2), true);
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
  std::string key_type_1 = AesGcmKeyManager::static_key_type();

  std::unique_ptr<TestAeadKeyManager> null_key_manager = nullptr;
  auto status = Registry::RegisterKeyManager(std::move(null_key_manager), true);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code()) << status;

  // Register a key manager.
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_1), true);
  EXPECT_TRUE(status.ok()) << status;

  // Register the same key manager again, it should work (idempotence).
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_1), true);
  EXPECT_TRUE(status.ok()) << status;

  // Try overriding a key manager.
  status =
      Registry::RegisterKeyManager(absl::make_unique<AesGcmKeyManager>(), true);
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

  std::unique_ptr<TestAeadCatalogue> null_catalogue = nullptr;
  auto status =
      Registry::AddCatalogue(catalogue_name, std::move(null_catalogue));
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code()) << status;

  // Add a catalogue.
  status = Registry::AddCatalogue(catalogue_name,
                                  absl::make_unique<TestAeadCatalogue>());
  EXPECT_TRUE(status.ok()) << status;

  // Add the same catalogue again, it should work (idempotence).
  status = Registry::AddCatalogue(catalogue_name,
                                  absl::make_unique<TestAeadCatalogue>());
  EXPECT_TRUE(status.ok()) << status;

  // Try overriding a catalogue.
  status = Registry::AddCatalogue(catalogue_name,
                                  absl::make_unique<AeadCatalogue>());
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
  std::string key_type_1 = "google.crypto.tink.AesCtrHmacAeadKey";
  std::string key_type_2 = "google.crypto.tink.AesGcmKey";
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
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_1), true);
  EXPECT_TRUE(status.ok()) << status;
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_2), true);
  EXPECT_TRUE(status.ok()) << status;

  // Get and use primitives.
  std::string plaintext = "some data";
  std::string aad = "aad";

  // Key #1.
  {
    auto result = Registry::GetPrimitive<Aead>(keyset.key(0).key_data());
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead = std::move(result.ValueOrDie());
    EXPECT_EQ(DummyAead(key_type_1).Encrypt(plaintext, aad).ValueOrDie(),
              aead->Encrypt(plaintext, aad).ValueOrDie());
  }

  // Key #3.
  {
    auto result = Registry::GetPrimitive<Aead>(keyset.key(2).key_data());
    EXPECT_TRUE(result.ok()) << result.status();
    auto aead = std::move(result.ValueOrDie());
    EXPECT_EQ(DummyAead(key_type_2).Encrypt(plaintext, aad).ValueOrDie(),
              aead->Encrypt(plaintext, aad).ValueOrDie());
  }
}

TEST_F(RegistryTest, testNewKeyData) {
  std::string key_type_1 = "google.crypto.tink.AesCtrHmacAeadKey";
  std::string key_type_2 = "google.crypto.tink.AesGcmKey";
  std::string key_type_3 = "yet/another/keytype";

  // Register key managers.
  util::Status status;
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_1),
      /*new_key_allowed=*/true);
  EXPECT_TRUE(status.ok()) << status;
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_2),
      /*new_key_allowed=*/true);
  EXPECT_TRUE(status.ok()) << status;
  status = Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type_3),
      /*new_key_allowed=*/false);
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

TEST_F(RegistryTest, testGetPublicKeyData) {
  // Setup the registry.
  Registry::Reset();
  auto status = Registry::RegisterKeyManager(
      absl::make_unique<EciesAeadHkdfPrivateKeyManager>(), true);
  ASSERT_TRUE(status.ok()) << status;
  status =
      Registry::RegisterKeyManager(absl::make_unique<AesGcmKeyManager>(), true);
  ASSERT_TRUE(status.ok()) << status;

  // Get a test private key.
  auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED,
      HashType::SHA256, /* aes_gcm_key_size= */ 24);

  // Extract public key data and check.
  auto public_key_data_result = Registry::GetPublicKeyData(
      EciesAeadHkdfPrivateKeyManager::static_key_type(),
      ecies_key.SerializeAsString());
  EXPECT_TRUE(public_key_data_result.ok()) << public_key_data_result.status();
  auto public_key_data = std::move(public_key_data_result.ValueOrDie());
  EXPECT_EQ(EciesAeadHkdfPublicKeyManager::static_key_type(),
            public_key_data->type_url());
  EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC, public_key_data->key_material_type());
  EXPECT_EQ(ecies_key.public_key().SerializeAsString(),
            public_key_data->value());

  // Try with a wrong key type.
  auto wrong_key_type_result = Registry::GetPublicKeyData(
      AesGcmKeyManager::static_key_type(), ecies_key.SerializeAsString());
  EXPECT_FALSE(wrong_key_type_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            wrong_key_type_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "PrivateKeyFactory",
                      wrong_key_type_result.status().error_message());

  // Try with a bad serialized key.
  auto bad_key_result = Registry::GetPublicKeyData(
      EciesAeadHkdfPrivateKeyManager::static_key_type(),
      "some bad serialized key");
  EXPECT_FALSE(bad_key_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            bad_key_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Could not parse",
                      bad_key_result.status().error_message());
}

// Tests that if we register the same type of wrapper twice, the second call
// succeeds.
TEST_F(RegistryTest, RegisterWrapperTwice) {
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>())
          .ok());
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>())
          .ok());
}

// Tests that if we register different wrappers for the same primitive twice,
// the second call fails.
TEST_F(RegistryTest, RegisterDifferentWrappers) {
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>())
          .ok());
  util::Status result = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<TestWrapper<Aead>>());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, result.error_code());
}

// Tests that if we register different wrappers for different primitives, this
// returns ok.
TEST_F(RegistryTest, RegisterDifferentWrappersDifferentPrimitives) {
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<TestWrapper<Aead>>())
          .ok());
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<TestWrapper<Mac>>())
          .ok());
}

// Tests that if we do not register a wrapper, then calls to Wrap
// fail with "No wrapper registered" -- even if there is a wrapper for a
// different primitive registered.
TEST_F(RegistryTest, NoWrapperRegistered) {
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<TestWrapper<Mac>>())
          .ok());

  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> result =
      Registry::Wrap<Aead>(absl::make_unique<PrimitiveSet<Aead>>());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No wrapper registered",
                      result.status().error_message());
}

// Tests that if the wrapper fails, the error of the wrapped is forwarded
// in GetWrappedPrimitive.
TEST_F(RegistryTest, WrapperFails) {
  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<TestWrapper<Aead>>())
          .ok());

  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> result =
      Registry::Wrap<Aead>(absl::make_unique<PrimitiveSet<Aead>>());
  EXPECT_FALSE(result.ok());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "This is a test wrapper",
                      result.status().error_message());
}

// Tests that wrapping works as expected in the usual case.
TEST_F(RegistryTest, UsualWrappingTest) {
  Keyset keyset;

  keyset.add_key();
  keyset.mutable_key(0)->set_output_prefix_type(OutputPrefixType::TINK);
  keyset.mutable_key(0)->set_key_id(1234543);
  keyset.mutable_key(0)->set_status(KeyStatusType::ENABLED);
  keyset.add_key();
  keyset.mutable_key(1)->set_output_prefix_type(OutputPrefixType::LEGACY);
  keyset.mutable_key(1)->set_key_id(726329);
  keyset.mutable_key(1)->set_status(KeyStatusType::ENABLED);
  keyset.add_key();
  keyset.mutable_key(2)->set_output_prefix_type(OutputPrefixType::TINK);
  keyset.mutable_key(2)->set_key_id(7213743);
  keyset.mutable_key(2)->set_status(KeyStatusType::ENABLED);

  auto primitive_set = absl::make_unique<PrimitiveSet<Aead>>();
  ASSERT_TRUE(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyAead>("aead0"), keyset.key(0))
          .ok());
  ASSERT_TRUE(
      primitive_set
          ->AddPrimitive(absl::make_unique<DummyAead>("aead1"), keyset.key(1))
          .ok());
  auto entry_result = primitive_set->AddPrimitive(
      absl::make_unique<DummyAead>("primary_aead"), keyset.key(2));
  primitive_set->set_primary(entry_result.ValueOrDie());

  EXPECT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>())
          .ok());

  auto aead_result = Registry::Wrap<Aead>(std::move(primitive_set));
  EXPECT_TRUE(aead_result.ok()) << aead_result.status();
  std::unique_ptr<Aead> aead = std::move(aead_result.ValueOrDie());
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
  std::string ciphertext = encrypt_result.ValueOrDie();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "primary_aead", ciphertext);

  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
  EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());

  decrypt_result = aead->Decrypt("some bad ciphertext", aad);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                      decrypt_result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
