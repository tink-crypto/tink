// Copyright 2018 Google Inc.
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

#include "tink/daead/deterministic_aead_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/daead/failing_daead.h"
#include "tink/deterministic_aead.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/monitoring/monitoring_client_mocks.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::DummyDeterministicAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::ByMove;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::Test;

namespace crypto {
namespace tink {
namespace {

class DeterministicAeadSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(DeterministicAeadSetWrapperTest, testBasic) {
  {  // daead_set is nullptr.
    auto daead_result =
        DeterministicAeadWrapper().Wrap(nullptr);
    EXPECT_FALSE(daead_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal, daead_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(daead_result.status().message()));
  }

  {  // daead_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<DeterministicAead>> daead_set(
        new PrimitiveSet<DeterministicAead>());
    auto daead_result =
        DeterministicAeadWrapper().Wrap(std::move(daead_set));
    EXPECT_FALSE(daead_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              daead_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(daead_result.status().message()));
  }

  {  // Correct daead_set;
    KeysetInfo::KeyInfo* key_info;
    KeysetInfo keyset_info;

    uint32_t key_id_0 = 1234543;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_key_id(key_id_0);
    key_info->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_1 = 726329;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
    key_info->set_key_id(key_id_1);
    key_info->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_2 = 7213743;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_key_id(key_id_2);
    key_info->set_status(KeyStatusType::ENABLED);

    std::string daead_name_0 = "daead0";
    std::string daead_name_1 = "daead1";
    std::string daead_name_2 = "daead2";
    std::unique_ptr<PrimitiveSet<DeterministicAead>> daead_set(
        new PrimitiveSet<DeterministicAead>());
    std::unique_ptr<DeterministicAead> daead(
        new DummyDeterministicAead(daead_name_0));
    auto entry_result =
        daead_set->AddPrimitive(std::move(daead), keyset_info.key_info(0));
    ASSERT_TRUE(entry_result.ok());
    daead = absl::make_unique<DummyDeterministicAead>(daead_name_1);
    entry_result =
        daead_set->AddPrimitive(std::move(daead), keyset_info.key_info(1));
    ASSERT_TRUE(entry_result.ok());
    daead = absl::make_unique<DummyDeterministicAead>(daead_name_2);
    entry_result =
        daead_set->AddPrimitive(std::move(daead), keyset_info.key_info(2));
    ASSERT_TRUE(entry_result.ok());
    // The last key is the primary.
    ASSERT_THAT(daead_set->set_primary(entry_result.value()), IsOk());

    // Wrap daead_set and test the resulting DeterministicAead.
    auto daead_result =
        DeterministicAeadWrapper().Wrap(std::move(daead_set));
    EXPECT_TRUE(daead_result.ok()) << daead_result.status();
    daead = std::move(daead_result.value());
    std::string plaintext = "some_plaintext";
    std::string associated_data = "some_associated_data";

    auto encrypt_result =
        daead->EncryptDeterministically(plaintext, associated_data);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    std::string ciphertext = encrypt_result.value();
    EXPECT_PRED_FORMAT2(testing::IsSubstring, daead_name_2, ciphertext);

    auto decrypt_result =
        daead->DecryptDeterministically(ciphertext, associated_data);
    EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
    EXPECT_EQ(plaintext, decrypt_result.value());

    decrypt_result =
        daead->DecryptDeterministically("some bad ciphertext", associated_data);
    EXPECT_FALSE(decrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              decrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                        std::string(decrypt_result.status().message()));
  }
}

KeysetInfo::KeyInfo PopulateKeyInfo(uint32_t key_id,
                                    OutputPrefixType out_prefix_type,
                                    KeyStatusType status) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(out_prefix_type);
  key_info.set_key_id(key_id);
  key_info.set_status(status);
  return key_info;
}

// Creates a test keyset info object.
KeysetInfo CreateTestKeysetInfo() {
  KeysetInfo keyset_info;
  *keyset_info.add_key_info() =
      PopulateKeyInfo(/*key_id=*/1234543, OutputPrefixType::TINK,
                      /*status=*/KeyStatusType::ENABLED);
  *keyset_info.add_key_info() =
      PopulateKeyInfo(/*key_id=*/726329, OutputPrefixType::LEGACY,
                      /*status=*/KeyStatusType::ENABLED);
  *keyset_info.add_key_info() =
      PopulateKeyInfo(/*key_id=*/7213743, OutputPrefixType::TINK,
                      /*status=*/KeyStatusType::ENABLED);
  return keyset_info;
}

// Tests for the monitoring behavior.
class DeterministicAeadSetWrapperWithMonitoringTest : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();

    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        absl::make_unique<MockMonitoringClientFactory>();
    auto encryption_monitoring_client =
        absl::make_unique<NiceMock<MockMonitoringClient>>();
    encryption_monitoring_client_ = encryption_monitoring_client.get();
    auto decryption_monitoring_client =
        absl::make_unique<NiceMock<MockMonitoringClient>>();
    decryption_monitoring_client_ = decryption_monitoring_client.get();

    // Monitoring tests expect that the client factory will create the
    // corresponding MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(
            Return(ByMove(util::StatusOr<std::unique_ptr<MonitoringClient>>(
                std::move(encryption_monitoring_client)))))
        .WillOnce(
            Return(ByMove(util::StatusOr<std::unique_ptr<MonitoringClient>>(
                std::move(decryption_monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~DeterministicAeadSetWrapperWithMonitoringTest() override {
    Registry::Reset();
  }

  MockMonitoringClient* encryption_monitoring_client_;
  MockMonitoringClient* decryption_monitoring_client_;
};

// Test that successful encrypt operations are logged.
TEST_F(DeterministicAeadSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringEncryptSuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto daead_primitive_set =
      absl::make_unique<PrimitiveSet<DeterministicAead>>(annotations);
  ASSERT_THAT(
      daead_primitive_set
          ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("daead0"),
                         keyset_info.key_info(0))
          , IsOk());
  ASSERT_THAT(
      daead_primitive_set
          ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("daead1"),
                         keyset_info.key_info(1))
          , IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<DeterministicAead>::Entry<DeterministicAead>*>
      last = daead_primitive_set->AddPrimitive(
          absl::make_unique<DummyDeterministicAead>("daead2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(daead_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();

  // Create a deterministic AEAD and encrypt some data.
  util::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      DeterministicAeadWrapper().Wrap(std::move(daead_primitive_set));
  ASSERT_THAT(daead, IsOkAndHolds(NotNull()));

  constexpr absl::string_view plaintext = "This is some plaintext!";
  constexpr absl::string_view associated_data = "Some associated data!";

  // Check that calling EncryptDeterministically triggers a Log() call.
  EXPECT_CALL(*encryption_monitoring_client_,
              Log(primary_key_id, plaintext.size()));
  util::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministically(plaintext, associated_data);
  EXPECT_THAT(ciphertext, IsOk());
}

// Test that successful encrypt operations are logged.
TEST_F(DeterministicAeadSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringDecryptSuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto daead_primitive_set =
      absl::make_unique<PrimitiveSet<DeterministicAead>>(annotations);
  ASSERT_THAT(
      daead_primitive_set
          ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("daead0"),
                         keyset_info.key_info(0))
          .status(),
      IsOk());
  ASSERT_THAT(
      daead_primitive_set
          ->AddPrimitive(absl::make_unique<DummyDeterministicAead>("daead1"),
                         keyset_info.key_info(1))
          .status(),
      IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<DeterministicAead>::Entry<DeterministicAead>*>
      last = daead_primitive_set->AddPrimitive(
          absl::make_unique<DummyDeterministicAead>("daead2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(daead_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();


  // Create a deterministic AEAD and encrypt/decrypt some data.
  util::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      DeterministicAeadWrapper().Wrap(std::move(daead_primitive_set));
  ASSERT_THAT(daead, IsOkAndHolds(NotNull()));

  constexpr absl::string_view plaintext = "This is some plaintext!";
  constexpr absl::string_view associated_data = "Some associated data!";


  // Check that calling DecryptDeterministically triggers a Log() call.
  util::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministically(plaintext, associated_data);
  EXPECT_THAT(ciphertext, IsOk());

  // In the log expect the size of the ciphertext without the non-raw prefix.
  EXPECT_CALL(*decryption_monitoring_client_,
              Log(primary_key_id,
                  ciphertext->size() - CryptoFormat::kNonRawPrefixSize));
  EXPECT_THAT(
      (*daead)->DecryptDeterministically(*ciphertext, associated_data).status(),
      IsOk());
}

TEST_F(DeterministicAeadSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringEncryptFailures) {
  // Create a primitive set and fill it with some entries.
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto daead_primitive_set =
      absl::make_unique<PrimitiveSet<DeterministicAead>>(annotations);
  ASSERT_THAT(daead_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingDeterministicAead("daead0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(daead_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingDeterministicAead("daead1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<DeterministicAead>::Entry<DeterministicAead>*>
      last = daead_primitive_set->AddPrimitive(
          CreateAlwaysFailingDeterministicAead("daead2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(daead_primitive_set->set_primary(*last), IsOk());


  // Create a deterministic AEAD and encrypt.
  util::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      DeterministicAeadWrapper().Wrap(std::move(daead_primitive_set));
  ASSERT_THAT(daead, IsOkAndHolds(NotNull()));

  constexpr absl::string_view plaintext = "This is some plaintext!";
  constexpr absl::string_view associated_data = "Some associated data!";


  // Check that calling EncryptDeterministically triggers a LogFailure() call.
  EXPECT_CALL(*encryption_monitoring_client_, LogFailure());
  util::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministically(plaintext, associated_data);
  EXPECT_THAT(ciphertext.status(), StatusIs(absl::StatusCode::kInternal));
}

// Test that monitoring logs decryption failures correctly.
TEST_F(DeterministicAeadSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringDecryptFailures) {
  // Create a primitive set and fill it with some entries.
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto daead_primitive_set =
      absl::make_unique<PrimitiveSet<DeterministicAead>>(annotations);
  ASSERT_THAT(daead_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingDeterministicAead("daead0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(daead_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingDeterministicAead("daead1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<DeterministicAead>::Entry<DeterministicAead>*>
      last = daead_primitive_set->AddPrimitive(
          CreateAlwaysFailingDeterministicAead("daead2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(daead_primitive_set->set_primary(*last), IsOk());


  // Create a deterministic AEAD and decrypt.
  util::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      DeterministicAeadWrapper().Wrap(std::move(daead_primitive_set));
  ASSERT_THAT(daead, IsOkAndHolds(NotNull()));

  constexpr absl::string_view associated_data = "Some associated data!";
  constexpr absl::string_view ciphertext = "This is some ciphertext!";


  // Check that calling DecryptDeterministically triggers a LogFailure() call.
  EXPECT_CALL(*decryption_monitoring_client_, LogFailure());
  EXPECT_THAT(
      (*daead)->DecryptDeterministically(ciphertext, associated_data).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
