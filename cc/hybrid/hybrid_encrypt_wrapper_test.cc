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

#include "tink/hybrid/hybrid_encrypt_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/hybrid/failing_hybrid.h"
#include "tink/hybrid_encrypt.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/monitoring/monitoring_client_mocks.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::DummyHybridEncrypt;
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

class HybridEncryptSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(HybridEncryptSetWrapperTest, testBasic) {
  { // hybrid_encrypt_set is nullptr.
    auto hybrid_encrypt_result =
        HybridEncryptWrapper().Wrap(nullptr);
    EXPECT_FALSE(hybrid_encrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal,
        hybrid_encrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(hybrid_encrypt_result.status().message()));
  }

  { // hybrid_encrypt_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<HybridEncrypt>>
        hybrid_encrypt_set(new PrimitiveSet<HybridEncrypt>());
    auto hybrid_encrypt_result = HybridEncryptWrapper().Wrap(
        std::move(hybrid_encrypt_set));
    EXPECT_FALSE(hybrid_encrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
        hybrid_encrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(hybrid_encrypt_result.status().message()));
  }

  { // Correct hybrid_encrypt_set;
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

    std::string hybrid_name_0 = "hybrid_0";
    std::string hybrid_name_1 = "hybrid_1";
    std::string hybrid_name_2 = "hybrid_2";
    std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set(
        new PrimitiveSet<HybridEncrypt>());
    std::unique_ptr<HybridEncrypt> hybrid_encrypt(
        new DummyHybridEncrypt(hybrid_name_0));
    auto entry_result = hybrid_encrypt_set->AddPrimitive(
        std::move(hybrid_encrypt), keyset_info.key_info(0));
    ASSERT_TRUE(entry_result.ok());
    hybrid_encrypt.reset(new DummyHybridEncrypt(hybrid_name_1));
    entry_result = hybrid_encrypt_set->AddPrimitive(std::move(hybrid_encrypt),
                                                    keyset_info.key_info(1));
    ASSERT_TRUE(entry_result.ok());
    hybrid_encrypt.reset(new DummyHybridEncrypt(hybrid_name_2));
    entry_result = hybrid_encrypt_set->AddPrimitive(std::move(hybrid_encrypt),
                                                    keyset_info.key_info(2));
    ASSERT_TRUE(entry_result.ok());
    // The last key is the primary.
    ASSERT_THAT(hybrid_encrypt_set->set_primary(entry_result.value()), IsOk());

    // Wrap hybrid_encrypt_set and test the resulting HybridEncrypt.
    auto hybrid_encrypt_result = HybridEncryptWrapper().Wrap(
        std::move(hybrid_encrypt_set));
    EXPECT_TRUE(hybrid_encrypt_result.ok()) << hybrid_encrypt_result.status();
    hybrid_encrypt = std::move(hybrid_encrypt_result.value());
    std::string plaintext = "some_plaintext";
    std::string context_info = "some_context";

    auto encrypt_result = hybrid_encrypt->Encrypt(plaintext, context_info);
    EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
    std::string ciphertext = encrypt_result.value();
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
        hybrid_name_2, ciphertext);
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
class HybridEncryptSetWrapperWithMonitoringTest : public Test {
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

    // Monitoring tests expect that the client factory will create the
    // corresponding MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(
            Return(ByMove(util::StatusOr<std::unique_ptr<MonitoringClient>>(
                std::move(encryption_monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~HybridEncryptSetWrapperWithMonitoringTest() override { Registry::Reset(); }

  MockMonitoringClient* encryption_monitoring_client_;
};

// Test that successful encrypt operations are logged.
TEST_F(HybridEncryptSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringEncryptSuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto hybrid_encrypt_primitive_set =
      absl::make_unique<PrimitiveSet<HybridEncrypt>>(annotations);
  ASSERT_THAT(
      hybrid_encrypt_primitive_set
          ->AddPrimitive(absl::make_unique<DummyHybridEncrypt>("hybrid0"),
                         keyset_info.key_info(0))
          , IsOk());
  ASSERT_THAT(
      hybrid_encrypt_primitive_set
          ->AddPrimitive(absl::make_unique<DummyHybridEncrypt>("hybrid1"),
                         keyset_info.key_info(1))
          , IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<HybridEncrypt>::Entry<HybridEncrypt>*>
      last = hybrid_encrypt_primitive_set->AddPrimitive(
          absl::make_unique<DummyHybridEncrypt>("hybrid2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(hybrid_encrypt_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();

  // Create a Hybrid Encrypt and encrypt some data.
  util::StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt =
      HybridEncryptWrapper().Wrap(std::move(hybrid_encrypt_primitive_set));
  ASSERT_THAT(hybrid_encrypt, IsOkAndHolds(NotNull()));

  constexpr absl::string_view plaintext = "This is some plaintext!";
  constexpr absl::string_view context = "Some context!";

  // Check that calling Encrypt triggers a Log() call.
  EXPECT_CALL(*encryption_monitoring_client_,
              Log(primary_key_id, plaintext.size()));
  util::StatusOr<std::string> ciphertext =
      (*hybrid_encrypt)->Encrypt(plaintext, context);
  EXPECT_THAT(ciphertext, IsOk());
}

TEST_F(HybridEncryptSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringEncryptFailures) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto hybrid_encrypt_primitive_set =
      absl::make_unique<PrimitiveSet<HybridEncrypt>>(annotations);
  ASSERT_THAT(hybrid_encrypt_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingHybridEncrypt("hybrid0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(hybrid_encrypt_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingHybridEncrypt("hybrid1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<HybridEncrypt>::Entry<HybridEncrypt>*> last =
      hybrid_encrypt_primitive_set->AddPrimitive(
          CreateAlwaysFailingHybridEncrypt("hybrid2"), keyset_info.key_info(2));
  ASSERT_THAT(last, IsOkAndHolds(NotNull()));
  ASSERT_THAT(hybrid_encrypt_primitive_set->set_primary(*last), IsOk());


  // Create a Hybrid Encrypt and encrypt some data.
  util::StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt =
      HybridEncryptWrapper().Wrap(std::move(hybrid_encrypt_primitive_set));
  ASSERT_THAT(hybrid_encrypt, IsOk());

  constexpr absl::string_view plaintext = "This is some plaintext!";
  constexpr absl::string_view context = "Some context!";

  // Check that calling Encrypt triggers a LogFailure() call.
  EXPECT_CALL(*encryption_monitoring_client_, LogFailure());
  util::StatusOr<std::string> ciphertext =
      (*hybrid_encrypt)->Encrypt(plaintext, context);
  EXPECT_THAT(ciphertext.status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
