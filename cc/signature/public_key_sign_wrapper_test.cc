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

#include "tink/signature/public_key_sign_wrapper.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/monitoring/monitoring_client_mocks.h"
#include "tink/primitive_set.h"
#include "tink/public_key_sign.h"
#include "tink/signature/failing_signature.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::ByMove;
using ::testing::IsNull;
using ::testing::StrictMock;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::Test;

namespace crypto {
namespace tink {
namespace {

TEST(PublicKeySignSetWrapperTest, TestBasic) {
  {  // pk_sign_set is nullptr.
    auto pk_sign_result =
        PublicKeySignWrapper().Wrap(/*primitive_set=*/nullptr);
    EXPECT_FALSE(pk_sign_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal, pk_sign_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(pk_sign_result.status().message()));
  }

  {  // pk_sign_set has no primary primitive.
    auto pk_sign_set = absl::make_unique<PrimitiveSet<PublicKeySign>>();
    auto pk_sign_result = PublicKeySignWrapper().Wrap(std::move(pk_sign_set));
    EXPECT_FALSE(pk_sign_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              pk_sign_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(pk_sign_result.status().message()));
  }

  {  // Correct pk_sign_set;
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
    key_info->set_output_prefix_type(OutputPrefixType::RAW);
    key_info->set_key_id(key_id_2);
    key_info->set_status(KeyStatusType::ENABLED);

    std::string signature_name_0 = "signature_0";
    std::string signature_name_1 = "signature_1";
    std::string signature_name_2 = "signature_2";
    std::unique_ptr<PrimitiveSet<PublicKeySign>> pk_sign_set(
        new PrimitiveSet<PublicKeySign>());

    std::unique_ptr<PublicKeySign> pk_sign(
        new DummyPublicKeySign(signature_name_0));
    auto entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset_info.key_info(0));
    ASSERT_THAT(entry_result, IsOk());

    pk_sign = absl::make_unique<DummyPublicKeySign>(signature_name_1);
    entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset_info.key_info(1));
    ASSERT_TRUE(entry_result.ok());

    pk_sign = absl::make_unique<DummyPublicKeySign>(signature_name_2);
    entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset_info.key_info(2));
    ASSERT_TRUE(entry_result.ok());

    // The last key is the primary.
    ASSERT_THAT(pk_sign_set->set_primary(entry_result.value()), IsOk());

    // Wrap pk_sign_set and test the resulting PublicKeySign.
    auto pk_sign_result = PublicKeySignWrapper().Wrap(std::move(pk_sign_set));
    EXPECT_TRUE(pk_sign_result.ok()) << pk_sign_result.status();
    pk_sign = std::move(pk_sign_result.value());
    std::string data = "some data to sign";
    auto sign_result = pk_sign->Sign(data);
    EXPECT_TRUE(sign_result.ok()) << sign_result.status();
    std::string signature = sign_result.value();
    std::unique_ptr<PublicKeyVerify> pk_verify(
        new DummyPublicKeyVerify(signature_name_2));
    auto verify_status = pk_verify->Verify(signature, data);
    EXPECT_TRUE(verify_status.ok()) << verify_status;
  }
}

TEST(PublicKeySignSetWrapperTest, TestLegacySignatures) {
  // Prepare a set for the wrapper.
  KeysetInfo::KeyInfo key;
  uint32_t key_id = 1234543;
  key.set_output_prefix_type(OutputPrefixType::LEGACY);
  key.set_key_id(key_id);
  key.set_status(KeyStatusType::ENABLED);
  std::string signature_name = "SomeLegacySignatures";

  std::unique_ptr<PrimitiveSet<PublicKeySign>> pk_sign_set(
      new PrimitiveSet<PublicKeySign>());
  std::string data = "Some data to sign";
  std::unique_ptr<PublicKeySign> pk_sign(
      new DummyPublicKeySign(signature_name));
  auto entry_result = pk_sign_set->AddPrimitive(std::move(pk_sign), key);
  ASSERT_THAT(entry_result, IsOk());
  ASSERT_THAT(pk_sign_set->set_primary(entry_result.value()), IsOk());

  // Wrap pk_sign_set and test the resulting PublicKeySign.
  auto pk_sign_result = PublicKeySignWrapper().Wrap(std::move(pk_sign_set));
  EXPECT_TRUE(pk_sign_result.ok()) << pk_sign_result.status();
  pk_sign = std::move(pk_sign_result.value());

  // Compute the signature via wrapper.
  auto sign_result = pk_sign->Sign(data);
  EXPECT_THAT(sign_result, IsOk());
  std::string signature = sign_result.value();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, signature_name, signature);

  // Try verifying on raw PublicKeyVerify-primitive using original data.
  std::unique_ptr<PublicKeyVerify> raw_pk_verify(
      new DummyPublicKeyVerify(signature_name));
  std::string raw_signature = signature.substr(CryptoFormat::kNonRawPrefixSize);
  auto status = raw_pk_verify->Verify(raw_signature, data);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());

  // Verify on raw PublicKeyVerify-primitive using legacy-formatted data.
  std::string legacy_data = data;
  legacy_data.append(1, CryptoFormat::kLegacyStartByte);
  status = raw_pk_verify->Verify(raw_signature, legacy_data);
  EXPECT_TRUE(status.ok()) << status;
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
class PublicKeySignSetWrapperWithMonitoringTest : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();

    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        absl::make_unique<MockMonitoringClientFactory>();
    auto sign_monitoring_client =
        absl::make_unique<StrictMock<MockMonitoringClient>>();
    sign_monitoring_client_ = sign_monitoring_client.get();

    // Monitoring tests expect that the client factory will create the
    // corresponding MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(
            Return(ByMove(util::StatusOr<std::unique_ptr<MonitoringClient>>(
                std::move(sign_monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~PublicKeySignSetWrapperWithMonitoringTest() override { Registry::Reset(); }

  MockMonitoringClient* sign_monitoring_client_;
};

// Test that successful sign operations are logged.
TEST_F(PublicKeySignSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringSignSuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto public_key_sign_primitive_set =
      absl::make_unique<PrimitiveSet<PublicKeySign>>(kAnnotations);
  ASSERT_THAT(public_key_sign_primitive_set
                  ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("sign0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(public_key_sign_primitive_set
                  ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("sign1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<PublicKeySign>::Entry<PublicKeySign>*> last =
      public_key_sign_primitive_set->AddPrimitive(
          absl::make_unique<DummyPublicKeySign>("sign2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(public_key_sign_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t kPrimaryKeyId = keyset_info.key_info(2).key_id();

  // Create a PublicKeySign primitive and sign some data.
  util::StatusOr<std::unique_ptr<PublicKeySign>> public_key_sign =
      PublicKeySignWrapper().Wrap(std::move(public_key_sign_primitive_set));
  ASSERT_THAT(public_key_sign, IsOkAndHolds(NotNull()));

  constexpr absl::string_view kMessage = "This is some message!";

  // Check that calling Sign triggers a Log() call.
  EXPECT_CALL(*sign_monitoring_client_, Log(kPrimaryKeyId, kMessage.size()));
  EXPECT_THAT((*public_key_sign)->Sign(kMessage), IsOk());
}

TEST_F(PublicKeySignSetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringSignFailures) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto public_key_sign_primitive_set =
      absl::make_unique<PrimitiveSet<PublicKeySign>>(kAnnotations);
  ASSERT_THAT(public_key_sign_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingPublicKeySign("sign0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(public_key_sign_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingPublicKeySign("sign1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<PublicKeySign>::Entry<PublicKeySign>*> last =
      public_key_sign_primitive_set->AddPrimitive(
          CreateAlwaysFailingPublicKeySign("sign2"), keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(public_key_sign_primitive_set->set_primary(*last), IsOk());

  // Create a PublicKeySign and sign some data.
  util::StatusOr<std::unique_ptr<PublicKeySign>> public_key_sign =
      PublicKeySignWrapper().Wrap(std::move(public_key_sign_primitive_set));
  ASSERT_THAT(public_key_sign, IsOkAndHolds(NotNull()));

  constexpr absl::string_view kPlaintext = "This is some message!";

  // Check that calling Sign triggers a LogFailure() call.
  EXPECT_CALL(*sign_monitoring_client_, LogFailure());
  EXPECT_THAT((*public_key_sign)->Sign(kPlaintext).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
