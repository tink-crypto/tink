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

#include <memory>
#include <thread>  // NOLINT(build/c++11)
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "tink/aead.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/catalogue.h"
#include "tink/config/tink_fips.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/key_type_manager.h"
#include "tink/crypto_format.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/keyset_manager.h"
#include "tink/registry.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::AddLegacyKey;
using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Status;
using ::google::crypto::tink::AesCtrHmacAeadKey;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaPrivateKey;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::portable_proto::MessageLite;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;

class RegistryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
  }

  void TearDown() override {
    // Reset is needed here to ensure Mock objects get deleted and do not leak.
    Registry::Reset();
  }
};

class TestKeyFactory : public KeyFactory {
 public:
  explicit TestKeyFactory(const std::string& key_type) : key_type_(key_type) {}

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> NewKey(
      const MessageLite& key_format) const override {
    return util::Status(absl::StatusCode::kUnknown,
                        "TestKeyFactory cannot produce a key");
  }

  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> NewKey(
      absl::string_view serialized_key_format) const override {
    return util::Status(absl::StatusCode::kUnknown,
                        "TestKeyFactory cannot produce a key");
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
  explicit TestAeadKeyManager(const std::string& key_type)
      : key_type_(key_type), key_factory_(key_type) {}

  util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitive(const KeyData& key) const override {
    std::unique_ptr<Aead> aead(new DummyAead(key_type_));
    return std::move(aead);
  }

  util::StatusOr<std::unique_ptr<Aead>>
  GetPrimitive(const MessageLite& key) const override {
    return util::Status(absl::StatusCode::kUnknown,
                        "TestKeyFactory cannot construct an aead");
  }


  uint32_t get_version() const override {
    return 0;
  }

  const std::string& get_key_type() const override { return key_type_; }

  const KeyFactory& get_key_factory() const override {
    return key_factory_;
  }

 private:
  std::string key_type_;
  TestKeyFactory key_factory_;
};

// A class for testing. We will construct objects from an aead key, so that we
// can check that a keymanager can handle multiple primitives. It is really
// insecure, as it does nothing except provide access to the key.
class AeadVariant {
 public:
  explicit AeadVariant(std::string s) : s_(s) {}

  std::string get() { return s_; }

 private:
  std::string s_;
};

class ExampleKeyTypeManager : public KeyTypeManager<AesGcmKey, AesGcmKeyFormat,
                                                    List<Aead, AeadVariant>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const AesGcmKey& key) const override {
      // Ignore the key and returned one with a fixed size for this test.
      return {subtle::AesGcmBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()))};
    }
  };

  class AeadVariantFactory : public PrimitiveFactory<AeadVariant> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<AeadVariant>> Create(
        const AesGcmKey& key) const override {
      return absl::make_unique<AeadVariant>(key.key_value());
    }
  };

  ExampleKeyTypeManager()
      : KeyTypeManager(absl::make_unique<AeadFactory>(),
                       absl::make_unique<AeadVariantFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  uint32_t get_version() const override { return kVersion; }

  const std::string& get_key_type() const override { return kKeyType; }

  crypto::tink::util::Status ValidateKey(const AesGcmKey& key) const override {
    return util::OkStatus();
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const AesGcmKeyFormat& key_format) const override {
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<AesGcmKey> CreateKey(
      const AesGcmKeyFormat& key_format) const override {
    AesGcmKey result;
    result.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
    return result;
  }

  crypto::tink::util::StatusOr<AesGcmKey> DeriveKey(
      const AesGcmKeyFormat& key_format,
      InputStream* input_stream) const override {
    // Note: in an actual key type manager we need to do more work, e.g., test
    // that the generated key is long enough.
    crypto::tink::util::StatusOr<std::string> randomness =
        ReadBytesFromStream(key_format.key_size(), input_stream);
    if (!randomness.status().ok()) {
      return randomness.status();
    }
    AesGcmKey key;
    key.set_key_value(randomness.ValueOrDie());
    return key;
  }

  MOCK_METHOD(FipsCompatibility, FipsStatus, (), (const, override));

 private:
  static constexpr int kVersion = 0;
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
};

template <typename P, typename Q = P>
class TestWrapper : public PrimitiveWrapper<P, Q> {
 public:
  TestWrapper() {}
  crypto::tink::util::StatusOr<std::unique_ptr<Q>> Wrap(
      std::unique_ptr<PrimitiveSet<P>> primitive_set) const override {
    return util::Status(util::error::UNIMPLEMENTED, "This is a test wrapper.");
  }
};

class AeadVariantWrapper : public PrimitiveWrapper<AeadVariant, AeadVariant> {
 public:
  crypto::tink::util::StatusOr<std::unique_ptr<AeadVariant>> Wrap(
      std::unique_ptr<PrimitiveSet<AeadVariant>> primitive_set) const override {
    return absl::make_unique<AeadVariant>(
        primitive_set->get_primary()->get_primitive().get());
  }
};

class AeadVariantToStringWrapper
    : public PrimitiveWrapper<AeadVariant, std::string> {
 public:
  crypto::tink::util::StatusOr<std::unique_ptr<std::string>> Wrap(
      std::unique_ptr<PrimitiveSet<AeadVariant>> primitive_set) const override {
    return absl::make_unique<std::string>(
        primitive_set->get_primary()->get_primitive().get());
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

  // Check that the managers were registered. Also, keep registering new
  // versions while we check.
  std::thread register_more_a(register_test_managers, key_type_prefix_a,
                              count_a);
  std::thread register_more_b(register_test_managers, key_type_prefix_b,
                              count_b);
  std::thread verify_a(verify_test_managers, key_type_prefix_a, count_a);
  std::thread verify_b(verify_test_managers, key_type_prefix_b, count_b);
  verify_a.join();
  verify_b.join();
  register_more_a.join();
  register_more_b.join();

  // Check that there are no extra managers.
  std::string key_type = key_type_prefix_a + std::to_string(count_a - 1);
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
  std::string key_type_1 = AesGcmKeyManager().get_key_type();

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
  AesGcmKeyManager key_type_manager;
  status = Registry::RegisterKeyManager(
      crypto::tink::internal::MakeKeyManager<Aead>(&key_type_manager), true);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code()) << status;

  // Check the key manager is still registered.
  auto manager_result = Registry::get_key_manager<Aead>(key_type_1);
  EXPECT_TRUE(manager_result.ok()) << manager_result.status();
  auto manager = manager_result.ValueOrDie();
  EXPECT_TRUE(manager->DoesSupport(key_type_1));
}

// Tests that if we register a key manager once more after a call to
// get_key_manager, the key manager previously obtained with "get_key_manager()"
// remains valid.
TEST_F(RegistryTest, GetKeyManagerRemainsValid) {
  std::string key_type = AesGcmKeyManager().get_key_type();
  EXPECT_THAT(Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type), true), IsOk());

  crypto::tink::util::StatusOr<const KeyManager<Aead>*> key_manager =
      Registry::get_key_manager<Aead>(key_type);
  ASSERT_THAT(key_manager.status(), IsOk());
  EXPECT_THAT(Registry::RegisterKeyManager(
                  absl::make_unique<TestAeadKeyManager>(key_type), true),
              IsOk());
  EXPECT_THAT(key_manager.ValueOrDie()->get_key_type(), Eq(key_type));
}

class TestAeadCatalogue : public Catalogue<Aead> {
 public:
  TestAeadCatalogue() {}

  util::StatusOr<std::unique_ptr<KeyManager<Aead>>> GetKeyManager(
      const std::string& type_url, const std::string& primitive_name,
      uint32_t min_version) const override {
    return util::Status(util::error::UNIMPLEMENTED,
                        "This is a test catalogue.");
  }
};

class TestAeadCatalogue2 : public TestAeadCatalogue {};

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
                                  absl::make_unique<TestAeadCatalogue2>());
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.error_code()) << status;

  // Check the catalogue is still present.
  EXPECT_THAT(Registry::get_catalogue<Aead>(catalogue_name).status(), IsOk());
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
  auto private_key_type_manager =
      absl::make_unique<EciesAeadHkdfPrivateKeyManager>();
  auto public_key_type_manager =
      absl::make_unique<EciesAeadHkdfPublicKeyManager>();

  auto status = Registry::RegisterKeyManager(
      internal::MakePrivateKeyManager<HybridDecrypt>(
          private_key_type_manager.get(), public_key_type_manager.get()),
      true);
  ASSERT_TRUE(status.ok()) << status;
  AesGcmKeyManager key_type_manager;
  status = Registry::RegisterKeyManager(
      crypto::tink::internal::MakeKeyManager<Aead>(&key_type_manager), true);
  ASSERT_TRUE(status.ok()) << status;

  // Get a test private key.
  auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED,
      HashType::SHA256, /* aes_gcm_key_size= */ 24);

  // Extract public key data and check.
  auto public_key_data_result = Registry::GetPublicKeyData(
      EciesAeadHkdfPrivateKeyManager().get_key_type(),
      ecies_key.SerializeAsString());
  EXPECT_TRUE(public_key_data_result.ok()) << public_key_data_result.status();
  auto public_key_data = std::move(public_key_data_result.ValueOrDie());
  EXPECT_EQ(EciesAeadHkdfPublicKeyManager().get_key_type(),
            public_key_data->type_url());
  EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC, public_key_data->key_material_type());
  EXPECT_EQ(ecies_key.public_key().SerializeAsString(),
            public_key_data->value());

  // Try with a wrong key type.
  auto wrong_key_type_result = Registry::GetPublicKeyData(
      AesGcmKeyManager().get_key_type(), ecies_key.SerializeAsString());
  EXPECT_FALSE(wrong_key_type_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            wrong_key_type_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "PrivateKeyFactory",
                      wrong_key_type_result.status().error_message());

  // Try with a bad serialized key.
  auto bad_key_result = Registry::GetPublicKeyData(
      EciesAeadHkdfPrivateKeyManager().get_key_type(),
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

// Tests that if we register the same type of wrapper twice, the second call
// succeeds.
TEST_F(RegistryTest, RegisterTransformingWrapperTwice) {
  EXPECT_TRUE(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<AeadVariantToStringWrapper>())
                  .ok());
  EXPECT_TRUE(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<AeadVariantToStringWrapper>())
                  .ok());
}

// Test that if we register a second wrapper, wrapping to the same type as a
// previous wrapper it will fail.
TEST_F(RegistryTest, RegisterTransformingWrapperTwiceMixing) {
  EXPECT_TRUE(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<AeadVariantToStringWrapper>())
                  .ok());
  // We cannot register a different wrapper creating a std::string.
  EXPECT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<TestWrapper<std::string>>()),
              Not(IsOk()));
  // But one creating an Aead.
  EXPECT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<TestWrapper<AeadVariant>>()),
              IsOk());
}

// Test that if we register a second wrapper, wrapping to the same type as a
// previous wrapper it will fail (order swapped).
TEST_F(RegistryTest, RegisterTransformingWrapperTwiceMixingBackwards) {
  EXPECT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<TestWrapper<std::string>>()),
              IsOk());
  // We cannot register another wrapper producing strings.
  EXPECT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<AeadVariantToStringWrapper>()),
              Not(IsOk()));
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
  EXPECT_EQ(util::error::NOT_FOUND, result.status().error_code());
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
  KeysetInfo keyset_info;

  keyset_info.add_key_info();
  keyset_info.mutable_key_info(0)->set_output_prefix_type(
      OutputPrefixType::TINK);
  keyset_info.mutable_key_info(0)->set_key_id(1234543);
  keyset_info.mutable_key_info(0)->set_status(KeyStatusType::ENABLED);
  keyset_info.add_key_info();
  keyset_info.mutable_key_info(1)->set_output_prefix_type(
      OutputPrefixType::LEGACY);
  keyset_info.mutable_key_info(1)->set_key_id(726329);
  keyset_info.mutable_key_info(1)->set_status(KeyStatusType::ENABLED);
  keyset_info.add_key_info();
  keyset_info.mutable_key_info(2)->set_output_prefix_type(
      OutputPrefixType::TINK);
  keyset_info.mutable_key_info(2)->set_key_id(7213743);
  keyset_info.mutable_key_info(2)->set_status(KeyStatusType::ENABLED);

  auto primitive_set = absl::make_unique<PrimitiveSet<Aead>>();
  ASSERT_TRUE(primitive_set
                  ->AddPrimitive(absl::make_unique<DummyAead>("aead0"),
                                 keyset_info.key_info(0))
                  .ok());
  ASSERT_TRUE(primitive_set
                  ->AddPrimitive(absl::make_unique<DummyAead>("aead1"),
                                 keyset_info.key_info(1))
                  .ok());
  auto entry_result = primitive_set->AddPrimitive(
      absl::make_unique<DummyAead>("primary_aead"), keyset_info.key_info(2));
  ASSERT_THAT(primitive_set->set_primary(entry_result.ValueOrDie()), IsOk());

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

std::string AddAesGcmKey(uint32_t key_id, OutputPrefixType output_prefix_type,
                         KeyStatusType key_status_type,
                         Keyset& modified_keyset) {
  AesGcmKey key;
  key.set_version(0);
  key.set_key_value(subtle::Random::GetRandomBytes(16));
  KeyData key_data;
  key_data.set_value(key.SerializeAsString());
  key_data.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  test::AddKeyData(key_data, key_id, output_prefix_type, key_status_type,
                   &modified_keyset);
  return key.key_value();
}

// Tests that wrapping of a keyset works in the usual case.
TEST_F(RegistryTest, KeysetWrappingTest) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Not supported when BoringSSL is not built in FIPS-mode.";
  }

  Keyset keyset;
  std::string raw_key =
      AddAesGcmKey(13, OutputPrefixType::TINK, KeyStatusType::ENABLED, keyset);
  keyset.set_primary_key_id(13);

  auto fips_key_manager = absl::make_unique<ExampleKeyTypeManager>();

  ON_CALL(*fips_key_manager, FipsStatus())
      .WillByDefault(testing::Return(FipsCompatibility::kRequiresBoringCrypto));

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  std::move(fips_key_manager), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<AeadVariantWrapper>()),
              IsOk());

  crypto::tink::util::StatusOr<std::unique_ptr<AeadVariant>> aead_variant =
      RegistryImpl::GlobalInstance().WrapKeyset<AeadVariant>(keyset);
  EXPECT_THAT(aead_variant.status(), IsOk());
  EXPECT_THAT(aead_variant.ValueOrDie()->get(), Eq(raw_key));
}

// Tests that wrapping of a keyset works.
TEST_F(RegistryTest, TransformingKeysetWrappingTest) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  Keyset keyset;
  std::string raw_key =
      AddAesGcmKey(13, OutputPrefixType::TINK, KeyStatusType::ENABLED, keyset);
  keyset.set_primary_key_id(13);

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<AeadVariantToStringWrapper>()),
              IsOk());

  crypto::tink::util::StatusOr<std::unique_ptr<std::string>> string_primitive =
      RegistryImpl::GlobalInstance().WrapKeyset<std::string>(keyset);
  EXPECT_THAT(string_primitive.status(), IsOk());
  EXPECT_THAT(*string_primitive.ValueOrDie(), Eq(raw_key));
}

// Tests that when we ask the registry to wrap a PrimitiveSet<Aead> into an
// Aead, but the wrapper is in fact from something else into Aead, we give a
// correct error message.
TEST_F(RegistryTest, TransformingPrimitiveWrapperCustomKeyManager) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  // Register a transforming wrapper taking strings and making Aeads.
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<TestWrapper<std::string, Aead>>()),
              IsOk());

  KeysetInfo keyset_info;
  keyset_info.add_key_info();
  keyset_info.mutable_key_info(0)->set_output_prefix_type(
      OutputPrefixType::TINK);
  keyset_info.mutable_key_info(0)->set_key_id(1234543);
  keyset_info.mutable_key_info(0)->set_status(KeyStatusType::ENABLED);
  keyset_info.set_primary_key_id(1234543);

  auto primitive_set = absl::make_unique<PrimitiveSet<Aead>>();
  ASSERT_TRUE(primitive_set
                  ->AddPrimitive(absl::make_unique<DummyAead>("aead0"),
                                 keyset_info.key_info(0))
                  .ok());

  EXPECT_THAT(Registry::Wrap<Aead>(std::move(primitive_set)).status(),
              StatusIs(util::error::FAILED_PRECONDITION,
                       HasSubstr("custom key manager")));
}

// Tests that the error message in GetKeyManager contains the type_id.name() of
// the primitive for which the key manager was actually registered.
TEST_F(RegistryTest, GetKeyManagerErrorMessage) {
  AesGcmKeyManager key_type_manager;
  EXPECT_TRUE(
      Registry::RegisterKeyManager(
          crypto::tink::internal::MakeKeyManager<Aead>(&key_type_manager), true)
          .ok());
  auto result =
      Registry::get_key_manager<int>(AesGcmKeyManager().get_key_type());
  EXPECT_FALSE(result.ok());
  EXPECT_THAT(result.status().error_message(),
              HasSubstr(AesGcmKeyManager().get_key_type()));
  // Note: The C++ standard does not guarantee the next line.  If some toolchain
  // update fails it, one can delete it.
  EXPECT_THAT(result.status().error_message(), HasSubstr(typeid(Aead).name()));
}

TEST_F(RegistryTest, RegisterKeyTypeManager) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
}

TEST_F(RegistryTest, RegisterFipsKeyTypeManager) {
  if (!kUseOnlyFips || !FIPS_mode()) {
    GTEST_SKIP() << "Only supported in FIPS-mode with BoringCrypto available.";
  }

  auto fips_key_manager = absl::make_unique<ExampleKeyTypeManager>();

  ON_CALL(*fips_key_manager, FipsStatus())
      .WillByDefault(testing::Return(FipsCompatibility::kRequiresBoringCrypto));

  EXPECT_THAT(
      Registry::RegisterKeyTypeManager(std::move(fips_key_manager), true),
      IsOk());
}

TEST_F(RegistryTest, RegisterFipsKeyTypeManagerNoBoringCrypto) {
  if (!kUseOnlyFips || FIPS_mode()) {
    GTEST_SKIP()
        << "Only supported in FIPS-mode with BoringCrypto not available.";
  }

  auto fips_key_manager = absl::make_unique<ExampleKeyTypeManager>();

  ON_CALL(*fips_key_manager, FipsStatus())
      .WillByDefault(testing::Return(FipsCompatibility::kNotFips));

  EXPECT_THAT(
      Registry::RegisterKeyTypeManager(std::move(fips_key_manager), true),
      StatusIs(util::error::INTERNAL));
}

TEST_F(RegistryTest, KeyTypeManagerGetFirstKeyManager) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  AesGcmKeyFormat format;
  format.set_key_size(16);
  AesGcmKey key = ExampleKeyTypeManager().CreateKey(format).ValueOrDie();
  auto aead = Registry::get_key_manager<Aead>(
                  "type.googleapis.com/google.crypto.tink.AesGcmKey")
                  .ValueOrDie()
                  ->GetPrimitive(key)
                  .ValueOrDie();
  std::string encryption = aead->Encrypt("TESTMESSAGE", "").ValueOrDie();
  std::string decryption = aead->Decrypt(encryption, "").ValueOrDie();
  EXPECT_THAT(decryption, Eq("TESTMESSAGE"));
}

TEST_F(RegistryTest, KeyTypeManagerGetSecondKeyManager) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  AesGcmKeyFormat format;
  format.set_key_size(16);
  AesGcmKey key = ExampleKeyTypeManager().CreateKey(format).ValueOrDie();
  auto aead_variant = Registry::get_key_manager<AeadVariant>(
                          "type.googleapis.com/google.crypto.tink.AesGcmKey")
                          .ValueOrDie()
                          ->GetPrimitive(key)
                          .ValueOrDie();
  EXPECT_THAT(aead_variant->get(), Eq(key.key_value()));
}

TEST_F(RegistryTest, KeyTypeManagerNotSupportedPrimitive) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<Mac>(
                  "type.googleapis.com/google.crypto.tink.AesGcmKey")
                  .status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("not among supported primitives")));
}

// Tests that if we register a key manager once more after a call to
// get_key_manager, the key manager previously obtained with "get_key_manager()"
// remains valid.
TEST_F(RegistryTest, GetKeyManagerRemainsValidForKeyTypeManagers) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());

  crypto::tink::util::StatusOr<const KeyManager<Aead>*> key_manager =
      Registry::get_key_manager<Aead>(ExampleKeyTypeManager().get_key_type());
  ASSERT_THAT(key_manager.status(), IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(key_manager.ValueOrDie()->get_key_type(),
              Eq(ExampleKeyTypeManager().get_key_type()));
}

TEST_F(RegistryTest, KeyTypeManagerNewKey) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());

  AesGcmKeyFormat format;
  format.set_key_size(32);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_value(format.SerializeAsString());

  KeyData key_data = *Registry::NewKeyData(key_template).ValueOrDie();
  EXPECT_THAT(key_data.type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(key_data.key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
  AesGcmKey key;
  key.ParseFromString(key_data.value());
  EXPECT_THAT(key.key_value(), SizeIs(32));
}

TEST_F(RegistryTest, KeyTypeManagerNewKeyInvalidSize) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());

  AesGcmKeyFormat format;
  format.set_key_size(33);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_value(format.SerializeAsString());

  EXPECT_THAT(Registry::NewKeyData(key_template).status(), IsOk());
}

TEST_F(RegistryTest, KeyTypeManagerDeriveKey) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());

  AesGcmKeyFormat format;
  format.set_key_size(32);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_value(format.SerializeAsString());

  crypto::tink::util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>(
          "0123456789012345678901234567890123456789")};

  auto key_data_or =
      RegistryImpl::GlobalInstance().DeriveKey(key_template, &input_stream);
  ASSERT_THAT(key_data_or.status(), IsOk());
  EXPECT_THAT(key_data_or.ValueOrDie().type_url(), Eq(key_template.type_url()));
  AesGcmKey key;
  EXPECT_TRUE(key.ParseFromString(key_data_or.ValueOrDie().value()));
  // 32 byte prefix of above string.
  EXPECT_THAT(key.key_value(), Eq("01234567890123456789012345678901"));
}

// The same, but we register the key manager twice. This should catch some of
// the possible lifetime issues.
TEST_F(RegistryTest, KeyTypeManagerDeriveKeyRegisterTwice) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());

  AesGcmKeyFormat format;
  format.set_key_size(32);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_value(format.SerializeAsString());

  crypto::tink::util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>(
          "0123456789012345678901234567890123456789")};

  auto key_data_or =
      RegistryImpl::GlobalInstance().DeriveKey(key_template, &input_stream);
  ASSERT_THAT(key_data_or.status(), IsOk());
  EXPECT_THAT(key_data_or.ValueOrDie().type_url(), Eq(key_template.type_url()));
  AesGcmKey key;
  EXPECT_TRUE(key.ParseFromString(key_data_or.ValueOrDie().value()));
  // 32 byte prefix of above string.
  EXPECT_THAT(key.key_value(), Eq("01234567890123456789012345678901"));
}

// Tests that if we register a KeyManager instead of a KeyTypeManager, DeriveKey
// fails properly.
TEST_F(RegistryTest, KeyManagerDeriveKeyFail) {
  std::string key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";
  ASSERT_THAT(Registry::RegisterKeyManager(
      absl::make_unique<TestAeadKeyManager>(key_type),
      /* new_key_allowed= */ true), IsOk());

  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");

  EXPECT_THAT(
      RegistryImpl::GlobalInstance().DeriveKey(key_template, nullptr).status(),
      StatusIs(util::error::INVALID_ARGUMENT, HasSubstr("cannot derive")));
}

TEST_F(RegistryTest, KeyManagerDeriveNotRegistered) {
  KeyTemplate key_template;
  key_template.set_type_url("some_inexistent_keytype");

  EXPECT_THAT(
      RegistryImpl::GlobalInstance().DeriveKey(key_template, nullptr).status(),
      StatusIs(util::error::NOT_FOUND, HasSubstr("No manager")));
}

TEST_F(RegistryTest, RegisterKeyTypeManagerTwiceMoreRestrictive) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), false),
              IsOk());
}

TEST_F(RegistryTest, RegisterKeyTypeManagerTwice) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), false),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), false),
              IsOk());
}

TEST_F(RegistryTest, RegisterKeyTypeManagerLessRestrictive) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), false),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              StatusIs(util::error::ALREADY_EXISTS));
}

TEST_F(RegistryTest, RegisterKeyTypeManagerBeforeKeyManager) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyManager(
                  absl::make_unique<TestAeadKeyManager>(
                      "type.googleapis.com/google.crypto.tink.AesGcmKey"),
                  true),
              StatusIs(util::error::ALREADY_EXISTS));
}

TEST_F(RegistryTest, RegisterKeyTypeManagerAfterKeyManager) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::RegisterKeyManager(
                  absl::make_unique<TestAeadKeyManager>(
                      "type.googleapis.com/google.crypto.tink.AesGcmKey"),
                  true),
              IsOk());
  EXPECT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<ExampleKeyTypeManager>(), true),
              StatusIs(util::error::ALREADY_EXISTS));
}

class PrivatePrimitiveA {};
class PrivatePrimitiveB {};

class TestPrivateKeyTypeManager
    : public PrivateKeyTypeManager<EcdsaPrivateKey, EcdsaKeyFormat,
                                   EcdsaPublicKey,
                                   List<PrivatePrimitiveA, PrivatePrimitiveB>> {
 public:
  class PrivatePrimitiveAFactory : public PrimitiveFactory<PrivatePrimitiveA> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PrivatePrimitiveA>> Create(
        const EcdsaPrivateKey& key) const override {
      return util::Status(util::error::UNIMPLEMENTED, "Not implemented");
    }
  };
  class PrivatePrimitiveBFactory : public PrimitiveFactory<PrivatePrimitiveB> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PrivatePrimitiveB>> Create(
        const EcdsaPrivateKey& key) const override {
      return util::Status(util::error::UNIMPLEMENTED, "Not implemented");
    }
  };

  TestPrivateKeyTypeManager()
      : PrivateKeyTypeManager(absl::make_unique<PrivatePrimitiveAFactory>(),
                              absl::make_unique<PrivatePrimitiveBFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  uint32_t get_version() const override { return 0; }
  crypto::tink::util::Status ValidateKey(
      const EcdsaPrivateKey& key) const override {
    return crypto::tink::util::Status::OK;
  }
  crypto::tink::util::Status ValidateKeyFormat(
      const EcdsaKeyFormat& key) const override {
    return crypto::tink::util::Status::OK;
  }

  const std::string& get_key_type() const override { return kKeyType; }

  crypto::tink::util::StatusOr<EcdsaPrivateKey> CreateKey(
      const EcdsaKeyFormat& key_format) const override {
    EcdsaPublicKey public_key;
    *public_key.mutable_params() = key_format.params();
    EcdsaPrivateKey result;
    *result.mutable_public_key() = public_key;
    return result;
  }

  crypto::tink::util::StatusOr<EcdsaPublicKey> GetPublicKey(
      const EcdsaPrivateKey& private_key) const override {
    return private_key.public_key();
  }

  MOCK_METHOD(FipsCompatibility, FipsStatus, (), (const, override));

 private:
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
};

class PublicPrimitiveA {};
class PublicPrimitiveB {};

class TestPublicKeyTypeManager
    : public KeyTypeManager<EcdsaPublicKey, void,
                            List<PublicPrimitiveA, PublicPrimitiveB>> {
 public:
  class PublicPrimitiveAFactory : public PrimitiveFactory<PublicPrimitiveA> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PublicPrimitiveA>> Create(
        const EcdsaPublicKey& key) const override {
      return util::Status(util::error::UNIMPLEMENTED, "Not implemented");
    }
  };
  class PublicPrimitiveBFactory : public PrimitiveFactory<PublicPrimitiveB> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PublicPrimitiveB>> Create(
        const EcdsaPublicKey& key) const override {
      return util::Status(util::error::UNIMPLEMENTED, "Not implemented");
    }
  };

  TestPublicKeyTypeManager()
      : KeyTypeManager(absl::make_unique<PublicPrimitiveAFactory>(),
                       absl::make_unique<PublicPrimitiveBFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  uint32_t get_version() const override { return 0; }
  crypto::tink::util::Status ValidateKey(
      const EcdsaPublicKey& key) const override {
    return crypto::tink::util::Status::OK;
  }

  const std::string& get_key_type() const override { return kKeyType; }

  MOCK_METHOD(FipsCompatibility, FipsStatus, (), (const, override));

 private:
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
};

std::unique_ptr<TestPrivateKeyTypeManager>
CreateTestPrivateKeyManagerFipsCompatible() {
  auto private_key_manager = absl::make_unique<TestPrivateKeyTypeManager>();
  ON_CALL(*private_key_manager, FipsStatus())
      .WillByDefault(testing::Return(FipsCompatibility::kRequiresBoringCrypto));
  return private_key_manager;
}

std::unique_ptr<TestPublicKeyTypeManager>
CreateTestPublicKeyManagerFipsCompatible() {
  auto public_key_manager = absl::make_unique<TestPublicKeyTypeManager>();
  ON_CALL(*public_key_manager, FipsStatus())
      .WillByDefault(testing::Return(FipsCompatibility::kRequiresBoringCrypto));
  return public_key_manager;
}

TEST_F(RegistryTest, RegisterAsymmetricKeyManagers) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  crypto::tink::util::Status status = Registry::RegisterAsymmetricKeyManagers(
      CreateTestPrivateKeyManagerFipsCompatible(),
      CreateTestPublicKeyManagerFipsCompatible(), true);
  ASSERT_TRUE(status.ok()) << status;
}

TEST_F(RegistryTest, AsymmetricMoreRestrictiveNewKey) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());

  crypto::tink::util::Status status = Registry::RegisterAsymmetricKeyManagers(
      CreateTestPrivateKeyManagerFipsCompatible(),
      CreateTestPublicKeyManagerFipsCompatible(), false);
  ASSERT_TRUE(status.ok()) << status;
}

TEST_F(RegistryTest, AsymmetricSameNewKey) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  crypto::tink::util::Status status = Registry::RegisterAsymmetricKeyManagers(
      CreateTestPrivateKeyManagerFipsCompatible(),
      CreateTestPublicKeyManagerFipsCompatible(), true);
  ASSERT_TRUE(status.ok()) << status;

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), false)
                  .ok());
  status = Registry::RegisterAsymmetricKeyManagers(
      CreateTestPrivateKeyManagerFipsCompatible(),
      CreateTestPublicKeyManagerFipsCompatible(), false);
  ASSERT_TRUE(status.ok()) << status;
}

TEST_F(RegistryTest, AsymmetricLessRestrictiveGivesError) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  crypto::tink::util::Status status = Registry::RegisterAsymmetricKeyManagers(
      CreateTestPrivateKeyManagerFipsCompatible(),
      CreateTestPublicKeyManagerFipsCompatible(), false);
  ASSERT_TRUE(status.ok()) << status;
  EXPECT_THAT(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true),
              StatusIs(util::error::ALREADY_EXISTS,
                       HasSubstr("forbidden new key operation")));
}

// Tests that if we register asymmetric key managers once more after a call to
// get_key_manager, the key manager previously obtained with "get_key_manager()"
// remains valid.

TEST_F(RegistryTest, RegisterAsymmetricKeyManagersGetKeyManagerStaysValid) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_THAT(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true),
              IsOk());

  crypto::tink::util::StatusOr<const KeyManager<PrivatePrimitiveA>*>
      private_key_manager = Registry::get_key_manager<PrivatePrimitiveA>(
          TestPrivateKeyTypeManager().get_key_type());
  crypto::tink::util::StatusOr<const KeyManager<PublicPrimitiveA>*>
      public_key_manager = Registry::get_key_manager<PublicPrimitiveA>(
          TestPublicKeyTypeManager().get_key_type());

  ASSERT_THAT(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true),
              IsOk());

  EXPECT_THAT(private_key_manager.ValueOrDie()->get_key_type(),
              Eq(TestPrivateKeyTypeManager().get_key_type()));
  EXPECT_THAT(public_key_manager.ValueOrDie()->get_key_type(),
              Eq(TestPublicKeyTypeManager().get_key_type()));
}


TEST_F(RegistryTest, AsymmetricPrivateRegisterAlone) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  CreateTestPrivateKeyManagerFipsCompatible(), true)
                  .ok());
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  // Registering the same as asymmetric key managers must fail, because doing so
  // would mean we invalidate key managers previously obtained with
  // get_key_manager().
  ASSERT_FALSE(Registry::RegisterAsymmetricKeyManagers(
                   CreateTestPrivateKeyManagerFipsCompatible(),
                   CreateTestPublicKeyManagerFipsCompatible(), true)
                   .ok());
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  CreateTestPrivateKeyManagerFipsCompatible(), true)
                  .ok());
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
}

TEST_F(RegistryTest, AsymmetricGetPrimitiveA) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  crypto::tink::util::StatusOr<const KeyManager<PrivatePrimitiveA>*> km =
      Registry::get_key_manager<PrivatePrimitiveA>(
          TestPrivateKeyTypeManager().get_key_type());
  ASSERT_TRUE(km.ok()) << km.status();
  EXPECT_THAT(km.ValueOrDie()->get_key_type(),
              Eq(TestPrivateKeyTypeManager().get_key_type()));
}

TEST_F(RegistryTest, AsymmetricGetPrimitiveB) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  crypto::tink::util::StatusOr<const KeyManager<PrivatePrimitiveB>*> km =
      Registry::get_key_manager<PrivatePrimitiveB>(
          TestPrivateKeyTypeManager().get_key_type());
  ASSERT_TRUE(km.ok()) << km.status();
  EXPECT_THAT(km.ValueOrDie()->get_key_type(),
              Eq(TestPrivateKeyTypeManager().get_key_type()));
}

TEST_F(RegistryTest, AsymmetricGetPublicPrimitiveA) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  crypto::tink::util::StatusOr<const KeyManager<PublicPrimitiveA>*> km =
      Registry::get_key_manager<PublicPrimitiveA>(
          TestPublicKeyTypeManager().get_key_type());
  ASSERT_TRUE(km.ok()) << km.status();
  EXPECT_THAT(km.ValueOrDie()->get_key_type(),
              Eq(TestPublicKeyTypeManager().get_key_type()));
}

TEST_F(RegistryTest, AsymmetricGetPublicPrimitiveB) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  crypto::tink::util::StatusOr<const KeyManager<PublicPrimitiveB>*> km =
      Registry::get_key_manager<PublicPrimitiveB>(
          TestPublicKeyTypeManager().get_key_type());
  ASSERT_TRUE(km.ok()) << km.status();
  EXPECT_THAT(km.ValueOrDie()->get_key_type(),
              Eq(TestPublicKeyTypeManager().get_key_type()));
}

TEST_F(RegistryTest, AsymmetricGetWrongPrimitiveError) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  crypto::tink::util::StatusOr<const KeyManager<PublicPrimitiveA>*> km =
      Registry::get_key_manager<PublicPrimitiveA>(
          TestPrivateKeyTypeManager().get_key_type());
  EXPECT_THAT(km.status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("not among supported primitives")));
}

class PrivateKeyManagerImplTest : public testing::Test {
  void SetUp() override {
    Registry::Reset();
  }

  void TearDown() override {
    // Reset is needed here to ensure Mock objects get deleted and do not leak.
    Registry::Reset();
  }
};

TEST_F(PrivateKeyManagerImplTest, AsymmetricFactoryNewKeyFromMessage) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());

  EcdsaKeyFormat key_format;
  key_format.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
  KeyTemplate key_template;
  key_template.set_type_url(TestPrivateKeyTypeManager().get_key_type());
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  std::unique_ptr<KeyData> key_data =
      Registry::NewKeyData(key_template).ValueOrDie();
  EXPECT_THAT(key_data->type_url(),
              Eq(TestPrivateKeyTypeManager().get_key_type()));
  EcdsaPrivateKey private_key;
  private_key.ParseFromString(key_data->value());
  EXPECT_THAT(private_key.public_key().params().encoding(),
              Eq(EcdsaSignatureEncoding::DER));
}

TEST_F(PrivateKeyManagerImplTest, AsymmetricNewKeyDisallowed) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), true)
                  .ok());
  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  CreateTestPrivateKeyManagerFipsCompatible(),
                  CreateTestPublicKeyManagerFipsCompatible(), false)
                  .ok());

  KeyTemplate key_template;
  key_template.set_type_url(TestPrivateKeyTypeManager().get_key_type());
  EXPECT_THAT(Registry::NewKeyData(key_template).status(),
              StatusIs(util::error::INVALID_ARGUMENT, HasSubstr("not allow")));
}

TEST_F(RegistryTest, AsymmetricGetPublicKeyData) {
  if (kUseOnlyFips && !FIPS_mode()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  crypto::tink::util::Status status = Registry::RegisterAsymmetricKeyManagers(
      CreateTestPrivateKeyManagerFipsCompatible(),
      CreateTestPublicKeyManagerFipsCompatible(), true);
  EcdsaPrivateKey private_key;
  private_key.mutable_public_key()->mutable_params()->set_encoding(
      EcdsaSignatureEncoding::DER);

  std::unique_ptr<KeyData> key_data =
      Registry::GetPublicKeyData(TestPrivateKeyTypeManager().get_key_type(),
                                 private_key.SerializeAsString())
          .ValueOrDie();
  ASSERT_THAT(key_data->type_url(),
              Eq(TestPublicKeyTypeManager().get_key_type()));
  EcdsaPublicKey public_key;
  public_key.ParseFromString(key_data->value());
  EXPECT_THAT(public_key.params().encoding(), Eq(EcdsaSignatureEncoding::DER));
}

class TestPrivateKeyTypeManager2 : public TestPrivateKeyTypeManager {};
class TestPublicKeyTypeManager2 : public TestPublicKeyTypeManager {};

TEST_F(RegistryTest, RegisterAssymmetricReregistrationWithWrongClasses) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  absl::make_unique<TestPrivateKeyTypeManager>(),
                  absl::make_unique<TestPublicKeyTypeManager>(), true)
                  .ok());
  EXPECT_THAT(
      Registry::RegisterAsymmetricKeyManagers(
          absl::make_unique<TestPrivateKeyTypeManager2>(),
          absl::make_unique<TestPublicKeyTypeManager>(), true),
      StatusIs(util::error::ALREADY_EXISTS, HasSubstr("already registered")));
  EXPECT_THAT(
      Registry::RegisterAsymmetricKeyManagers(
          absl::make_unique<TestPrivateKeyTypeManager>(),
          absl::make_unique<TestPublicKeyTypeManager2>(), true),
      StatusIs(util::error::ALREADY_EXISTS, HasSubstr("already registered")));
  EXPECT_THAT(
      Registry::RegisterAsymmetricKeyManagers(
          absl::make_unique<TestPrivateKeyTypeManager2>(),
          absl::make_unique<TestPublicKeyTypeManager2>(), true),
      StatusIs(util::error::ALREADY_EXISTS, HasSubstr("already registered")));
  EXPECT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<TestPrivateKeyTypeManager2>(), true),
      StatusIs(util::error::ALREADY_EXISTS, HasSubstr("already registered")));
  EXPECT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<TestPublicKeyTypeManager2>(), true),
      StatusIs(util::error::ALREADY_EXISTS, HasSubstr("already registered")));
}

class TestPublicKeyTypeManagerWithDifferentKeyType
    : public TestPublicKeyTypeManager {
  const std::string& get_key_type() const override { return kKeyType; }

 private:
  const std::string kKeyType = "bla";
};

TEST_F(RegistryTest, RegisterAssymmetricReregistrationWithNewKeyType) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(Registry::RegisterAsymmetricKeyManagers(
                  absl::make_unique<TestPrivateKeyTypeManager>(),
                  absl::make_unique<TestPublicKeyTypeManager>(), true)
                  .ok());
  EXPECT_THAT(
      Registry::RegisterAsymmetricKeyManagers(
          absl::make_unique<TestPrivateKeyTypeManager>(),
          absl::make_unique<TestPublicKeyTypeManagerWithDifferentKeyType>(),
          true),
      StatusIs(util::error::INVALID_ARGUMENT,
               HasSubstr("impossible to register")));
}

// The DelegatingKeyTypeManager calls the registry
class DelegatingKeyTypeManager
    : public PrivateKeyTypeManager<EcdsaPrivateKey, EcdsaKeyFormat,
                                   EcdsaPublicKey, List<>> {
 public:
  DelegatingKeyTypeManager() : PrivateKeyTypeManager() {}

  void set_registry(RegistryImpl* registry) { registry_ = registry; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  uint32_t get_version() const override { return kVersion; }

  const std::string& get_key_type() const override { return kKeyType; }

  crypto::tink::util::Status ValidateKey(
      const EcdsaPrivateKey& key) const override {
    return util::OkStatus();
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const EcdsaKeyFormat& key_format) const override {
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<EcdsaPrivateKey> CreateKey(
      const EcdsaKeyFormat& key_format) const override {
    AesGcmKeyFormat format;
    KeyTemplate key_template;
    key_template.set_type_url(
        "type.googleapis.com/google.crypto.tink.AesGcmKey");
    key_template.set_value(format.SerializeAsString());
    auto result = registry_->NewKeyData(key_template);
    if (!result.ok()) return result.status();
    // Return a string we can check for.
    return util::Status(util::error::DEADLINE_EXCEEDED, "CreateKey worked");
  }

  crypto::tink::util::StatusOr<EcdsaPrivateKey> DeriveKey(
      const EcdsaKeyFormat& key_format,
      InputStream* input_stream) const override {
    AesGcmKeyFormat format;
    KeyTemplate key_template;
    key_template.set_type_url(
        "type.googleapis.com/google.crypto.tink.AesGcmKey");
    key_template.set_value(format.SerializeAsString());

    auto result = registry_->DeriveKey(key_template, input_stream);
    if (!result.ok()) return result.status();
    // Return a string we can check for.
    return util::Status(util::error::DEADLINE_EXCEEDED, "DeriveKey worked");
  }

  crypto::tink::util::StatusOr<EcdsaPublicKey> GetPublicKey(
      const EcdsaPrivateKey& private_key) const override {
    AesGcmKeyFormat format;
    KeyTemplate key_template;
    key_template.set_type_url(
        "type.googleapis.com/google.crypto.tink.AesGcmKey");
    key_template.set_value(format.SerializeAsString());
    auto result = registry_->NewKeyData(key_template);
    if (!result.ok()) return result.status();
    // Return a string we can check for.
    return util::Status(util::error::DEADLINE_EXCEEDED, "GetPublicKey worked");
  }

 private:
  RegistryImpl* registry_;

  static constexpr int kVersion = 0;
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
};

class RegistryImplTest : public ::testing::Test {
 protected:
  void TearDown() override {
    // Calling RestrictToFipsIfEmpty() may call SetFipsRestricted(), which
    // set a global variable to true. We have to reset that after the test.
    UnSetFipsRestricted();
  }
};

// Check that we can call the registry again from within NewKeyData
TEST_F(RegistryImplTest, CanDelegateCreateKey) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  RegistryImpl registry_impl;
  auto delegating_key_manager = absl::make_unique<DelegatingKeyTypeManager>();
  delegating_key_manager->set_registry(&registry_impl);
  auto status =
      registry_impl
          .RegisterKeyTypeManager<EcdsaPrivateKey, EcdsaKeyFormat, List<>>(
              std::move(delegating_key_manager), true);
  EXPECT_THAT(status, IsOk());
  status = registry_impl.RegisterKeyTypeManager<AesGcmKey, AesGcmKeyFormat,
                                                   List<Aead, AeadVariant>>(
                  absl::make_unique<ExampleKeyTypeManager>(), true);
  EXPECT_THAT(status, IsOk());

  EcdsaKeyFormat format;
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
  key_template.set_value(format.SerializeAsString());
  EXPECT_THAT(registry_impl.NewKeyData(key_template).status(),
              StatusIs(util::error::DEADLINE_EXCEEDED,
                       HasSubstr("CreateKey worked")));
}

// Check that we can call the registry again from within NewKeyData
TEST_F(RegistryImplTest, CanDelegateDeriveKey) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  RegistryImpl registry_impl;
  auto delegating_key_manager = absl::make_unique<DelegatingKeyTypeManager>();
  delegating_key_manager->set_registry(&registry_impl);
  auto status =
      registry_impl
          .RegisterKeyTypeManager<EcdsaPrivateKey, EcdsaKeyFormat, List<>>(
              std::move(delegating_key_manager), true);
  EXPECT_THAT(status, IsOk());
  status = registry_impl.RegisterKeyTypeManager<AesGcmKey, AesGcmKeyFormat,
                                                   List<Aead, AeadVariant>>(
                  absl::make_unique<ExampleKeyTypeManager>(), true);
  EXPECT_THAT(status, IsOk());

  EcdsaKeyFormat format;
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
  key_template.set_value(format.SerializeAsString());
  EXPECT_THAT(
      registry_impl.DeriveKey(key_template, nullptr).status(),
      StatusIs(util::error::DEADLINE_EXCEEDED, HasSubstr("DeriveKey worked")));
}

TEST_F(RegistryImplTest, CanDelegateGetPublicKey) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  RegistryImpl registry_impl;
  auto delegating_key_manager = absl::make_unique<DelegatingKeyTypeManager>();
  delegating_key_manager->set_registry(&registry_impl);
  auto status = registry_impl.RegisterAsymmetricKeyManagers(
      delegating_key_manager.release(),
      absl::make_unique<TestPublicKeyTypeManager>().release(), true);
  EXPECT_THAT(status, IsOk());
  status = registry_impl.RegisterKeyTypeManager<AesGcmKey, AesGcmKeyFormat,
                                                   List<Aead, AeadVariant>>(
                  absl::make_unique<ExampleKeyTypeManager>(), true);
  EXPECT_THAT(status, IsOk());

  EcdsaPrivateKey private_key;
  private_key.mutable_public_key()->mutable_params()->set_encoding(
      EcdsaSignatureEncoding::DER);

  EXPECT_THAT(registry_impl
                  .GetPublicKeyData(DelegatingKeyTypeManager().get_key_type(),
                                    private_key.SerializeAsString())
                  .status(),
              StatusIs(util::error::DEADLINE_EXCEEDED,
                       HasSubstr("GetPublicKey worked")));
}

TEST_F(RegistryImplTest, FipsSucceedsOnEmptyRegistry) {
  RegistryImpl registry_impl;
  EXPECT_THAT(registry_impl.RestrictToFipsIfEmpty(), IsOk());
}

TEST_F(RegistryImplTest, FipsFailsIfNotEmpty) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Not supported when BoringSSL is not built in FIPS-mode.";
  }

  auto fips_key_manager = absl::make_unique<ExampleKeyTypeManager>();
  ON_CALL(*fips_key_manager, FipsStatus())
      .WillByDefault(testing::Return(FipsCompatibility::kRequiresBoringCrypto));

  RegistryImpl registry_impl;
  auto status = registry_impl.RegisterKeyTypeManager<AesGcmKey, AesGcmKeyFormat,
                                                   List<Aead, AeadVariant>>(
                  std::move(fips_key_manager), true);
  EXPECT_THAT(status, IsOk());
  EXPECT_THAT(registry_impl.RestrictToFipsIfEmpty(),
              StatusIs(util::error::INTERNAL));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
