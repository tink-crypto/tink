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

#include "tink/hybrid/hybrid_decrypt_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/failing_hybrid.h"
#include "tink/hybrid_decrypt.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/monitoring/monitoring_client_mocks.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::DummyHybridDecrypt;
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

class HybridDecryptSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(HybridDecryptSetWrapperTest, Basic) {
  { // hybrid_decrypt_set is nullptr.
    auto hybrid_decrypt_result =
        HybridDecryptWrapper().Wrap(nullptr);
    EXPECT_FALSE(hybrid_decrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal,
              hybrid_decrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(hybrid_decrypt_result.status().message()));
  }

  { // hybrid_decrypt_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<HybridDecrypt>>
        hybrid_decrypt_set(new PrimitiveSet<HybridDecrypt>());
    auto hybrid_decrypt_result = HybridDecryptWrapper().Wrap(
        std::move(hybrid_decrypt_set));
    EXPECT_FALSE(hybrid_decrypt_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
        hybrid_decrypt_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(hybrid_decrypt_result.status().message()));
  }

  { // Correct hybrid_decrypt_set;
    KeysetInfo::KeyInfo* key;
    KeysetInfo keyset;

    uint32_t key_id_0 = 1234543;
    key = keyset.add_key_info();
    key->set_output_prefix_type(OutputPrefixType::RAW);
    key->set_key_id(key_id_0);
    key->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_1 = 726329;
    key = keyset.add_key_info();
    key->set_output_prefix_type(OutputPrefixType::LEGACY);
    key->set_key_id(key_id_1);
    key->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_2 = 7213743;
    key = keyset.add_key_info();
    key->set_output_prefix_type(OutputPrefixType::TINK);
    key->set_key_id(key_id_2);
    key->set_status(KeyStatusType::ENABLED);

    std::string hybrid_name_0 = "hybrid_0";
    std::string hybrid_name_1 = "hybrid_1";
    std::string hybrid_name_2 = "hybrid_2";
    std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set(
        new PrimitiveSet<HybridDecrypt>());
    std::unique_ptr<HybridDecrypt> hybrid_decrypt(
        new DummyHybridDecrypt(hybrid_name_0));
    auto entry_result = hybrid_decrypt_set->AddPrimitive(
        std::move(hybrid_decrypt), keyset.key_info(0));
    ASSERT_TRUE(entry_result.ok());
    hybrid_decrypt.reset(new DummyHybridDecrypt(hybrid_name_1));
    entry_result = hybrid_decrypt_set->AddPrimitive(std::move(hybrid_decrypt),
                                                    keyset.key_info(1));
    ASSERT_TRUE(entry_result.ok());
    std::string prefix_id_1 = entry_result.value()->get_identifier();
    hybrid_decrypt.reset(new DummyHybridDecrypt(hybrid_name_2));
    entry_result = hybrid_decrypt_set->AddPrimitive(std::move(hybrid_decrypt),
                                                    keyset.key_info(2));
    ASSERT_TRUE(entry_result.ok());
    // The last key is the primary.
    ASSERT_THAT(hybrid_decrypt_set->set_primary(entry_result.value()), IsOk());

    // Wrap hybrid_decrypt_set and test the resulting HybridDecrypt.
    auto hybrid_decrypt_result = HybridDecryptWrapper().Wrap(
        std::move(hybrid_decrypt_set));
    EXPECT_TRUE(hybrid_decrypt_result.ok()) << hybrid_decrypt_result.status();
    hybrid_decrypt = std::move(hybrid_decrypt_result.value());
    std::string plaintext = "some_plaintext";
    std::string context_info = "some_context";

    {  // RAW key
      std::string ciphertext = DummyHybridEncrypt(hybrid_name_0)
                                   .Encrypt(plaintext, context_info)
                                   .value();
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
      EXPECT_EQ(plaintext, decrypt_result.value());
    }

    {  // No ciphertext prefix.
      std::string ciphertext = plaintext + hybrid_name_1;
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_FALSE(decrypt_result.ok());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument,
                decrypt_result.status().code());
      EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                          std::string(decrypt_result.status().message()));
    }

    {  // Correct ciphertext prefix.
      std::string ciphertext =
          prefix_id_1 + DummyHybridEncrypt(hybrid_name_1)
                            .Encrypt(plaintext, context_info)
                            .value();
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
      EXPECT_EQ(plaintext, decrypt_result.value());
    }

    {  // Bad ciphertext.
      std::string ciphertext = "some bad ciphertext";
      auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
      EXPECT_FALSE(decrypt_result.ok());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument,
          decrypt_result.status().code());
      EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
                          std::string(decrypt_result.status().message()));
    }
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
class HybridDecryptSetWrapperWithMonitoringTest : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();

    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        absl::make_unique<MockMonitoringClientFactory>();
    auto decryption_monitoring_client =
        absl::make_unique<NiceMock<MockMonitoringClient>>();
    decryption_monitoring_client_ = decryption_monitoring_client.get();

    // Monitoring tests expect that the client factory will create the
    // corresponding MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
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
  ~HybridDecryptSetWrapperWithMonitoringTest() override { Registry::Reset(); }

  MockMonitoringClient* decryption_monitoring_client_;
};

// Test that successful encrypt operations are logged.
TEST_F(HybridDecryptSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringEncryptSuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto hybrid_decrypt_primitive_set =
      absl::make_unique<PrimitiveSet<HybridDecrypt>>(annotations);
  ASSERT_THAT(
      hybrid_decrypt_primitive_set
          ->AddPrimitive(absl::make_unique<DummyHybridDecrypt>("hybrid0"),
                         keyset_info.key_info(0))
          .status(),
      IsOk());
  ASSERT_THAT(
      hybrid_decrypt_primitive_set
          ->AddPrimitive(absl::make_unique<DummyHybridDecrypt>("hybrid1"),
                         keyset_info.key_info(1))
          .status(),
      IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<HybridDecrypt>::Entry<HybridDecrypt>*> last =
      hybrid_decrypt_primitive_set->AddPrimitive(
          absl::make_unique<DummyHybridDecrypt>("hybrid2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(hybrid_decrypt_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();

  // Create a Hybrid Encrypt and encrypt some data, so we can decrypt it later.
  util::StatusOr<std::unique_ptr<HybridDecrypt>> hybrid_decrypt =
      HybridDecryptWrapper().Wrap(std::move(hybrid_decrypt_primitive_set));
  ASSERT_THAT(hybrid_decrypt, IsOkAndHolds(NotNull()));

  constexpr absl::string_view plaintext = "This is some plaintext!";
  constexpr absl::string_view context = "Some context!";
  std::string ciphertext = absl::StrCat((*last)->get_identifier(),
      DummyHybridEncrypt("hybrid2").Encrypt(plaintext, context).value());

  // Check that calling Decrypt triggers a Log() call.
  EXPECT_CALL(*decryption_monitoring_client_,
             Log(primary_key_id, ciphertext.size()));
  EXPECT_THAT((*hybrid_decrypt)->Decrypt(ciphertext, context),
             IsOkAndHolds(plaintext));
}

TEST_F(HybridDecryptSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringEncryptFailures) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> annotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto hybrid_decrypt_primitive_set =
      absl::make_unique<PrimitiveSet<HybridDecrypt>>(annotations);
  ASSERT_THAT(hybrid_decrypt_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingHybridDecrypt("hybrid0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(hybrid_decrypt_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingHybridDecrypt("hybrid1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<HybridDecrypt>::Entry<HybridDecrypt>*> last =
      hybrid_decrypt_primitive_set->AddPrimitive(
          CreateAlwaysFailingHybridDecrypt("hybrid2"), keyset_info.key_info(2));
  ASSERT_THAT(last, IsOkAndHolds(NotNull()));
  ASSERT_THAT(hybrid_decrypt_primitive_set->set_primary(*last), IsOk());

  // Create a Hybrid Decrypt and decrypt some invalid ciphertext.
  util::StatusOr<std::unique_ptr<HybridDecrypt>> hybrid_decrypt =
      HybridDecryptWrapper().Wrap(std::move(hybrid_decrypt_primitive_set));
  ASSERT_THAT(hybrid_decrypt.status(), IsOk());

  constexpr absl::string_view ciphertext = "This is some ciphertext!";
  constexpr absl::string_view context = "Some context!";

  // Check that calling Decrypt triggers a LogFailure() call.
  EXPECT_CALL(*decryption_monitoring_client_, LogFailure());
  EXPECT_THAT((*hybrid_decrypt)->Decrypt(ciphertext, context).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
