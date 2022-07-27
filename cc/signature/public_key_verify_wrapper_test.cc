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

#include "tink/signature/public_key_verify_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/primitive_set.h"
#include "tink/public_key_verify.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/monitoring/monitoring_client_mocks.h"
#include "tink/signature/failing_signature.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

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

class PublicKeyVerifySetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(PublicKeyVerifySetWrapperTest, testBasic) {
  { // pk_verify_set is nullptr.
    auto pk_verify_result = PublicKeyVerifyWrapper().Wrap(nullptr);
    EXPECT_FALSE(pk_verify_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal, pk_verify_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(pk_verify_result.status().message()));
  }

  { // pk_verify_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<PublicKeyVerify>>
        pk_verify_set(new PrimitiveSet<PublicKeyVerify>());
    auto pk_verify_result =
        PublicKeyVerifyWrapper().Wrap(std::move(pk_verify_set));
    EXPECT_FALSE(pk_verify_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
        pk_verify_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(pk_verify_result.status().message()));
  }

  { // Correct pk_verify_set;
    KeysetInfo::KeyInfo* key_info;
    KeysetInfo keyset_info;

    uint32_t key_id_0 = 1234543;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::RAW);
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

    std::string signature_name_0 = "signature_0";
    std::string signature_name_1 = "signature_1";
    std::string signature_name_2 = "signature_2";
    std::unique_ptr<PrimitiveSet<PublicKeyVerify>> pk_verify_set(
        new PrimitiveSet<PublicKeyVerify>());

    std::unique_ptr<PublicKeyVerify> pk_verify(
        new DummyPublicKeyVerify(signature_name_0));
    auto entry_result = pk_verify_set->AddPrimitive(std::move(pk_verify),
                                                    keyset_info.key_info(0));
    ASSERT_TRUE(entry_result.ok());

    pk_verify.reset(new DummyPublicKeyVerify(signature_name_1));
    entry_result = pk_verify_set->AddPrimitive(std::move(pk_verify),
                                               keyset_info.key_info(1));
    ASSERT_TRUE(entry_result.ok());

    pk_verify.reset(new DummyPublicKeyVerify(signature_name_2));
    entry_result = pk_verify_set->AddPrimitive(std::move(pk_verify),
                                               keyset_info.key_info(2));
    ASSERT_TRUE(entry_result.ok());

    // The last key is the primary.
    ASSERT_THAT(pk_verify_set->set_primary(entry_result.value()), IsOk());

    // Wrap pk_verify_set and test the resulting PublicKeyVerify.
    auto pk_verify_result =
        PublicKeyVerifyWrapper().Wrap(std::move(pk_verify_set));
    EXPECT_TRUE(pk_verify_result.ok()) << pk_verify_result.status();
    pk_verify = std::move(pk_verify_result.value());
    std::string data = "some data to sign";
    std::unique_ptr<PublicKeySign> pk_sign(
        new DummyPublicKeySign(signature_name_0));
    std::string signature = pk_sign->Sign(data).value();
    util::Status status = pk_verify->Verify(signature, data);
    EXPECT_TRUE(status.ok()) << status;
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
class PublicKeyVerifySetWrapperWithMonitoringTest : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();

    // Setup mocks for catching Monitoring calls.
    auto monitoring_client_factory =
        absl::make_unique<MockMonitoringClientFactory>();
    auto verify_monitoring_client =
        absl::make_unique<StrictMock<MockMonitoringClient>>();
    verify_monitoring_client_ = verify_monitoring_client.get();

    // Monitoring tests expect that the client factory will create the
    // corresponding MockMonitoringClients.
    EXPECT_CALL(*monitoring_client_factory, New(_))
        .WillOnce(
            Return(ByMove(util::StatusOr<std::unique_ptr<MonitoringClient>>(
                std::move(verify_monitoring_client)))));

    ASSERT_THAT(internal::RegistryImpl::GlobalInstance()
                    .RegisterMonitoringClientFactory(
                        std::move(monitoring_client_factory)),
                IsOk());
    ASSERT_THAT(
        internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory(),
        Not(IsNull()));
  }

  // Cleanup the registry to avoid mock leaks.
  ~PublicKeyVerifySetWrapperWithMonitoringTest() override { Registry::Reset(); }

  MockMonitoringClient* verify_monitoring_client_;
};

// Test that successful sign operations are logged.
TEST_F(PublicKeyVerifySetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringVerifySuccess) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto public_key_verify_primitive_set =
      absl::make_unique<PrimitiveSet<PublicKeyVerify>>(kAnnotations);
  ASSERT_THAT(
      public_key_verify_primitive_set
          ->AddPrimitive(absl::make_unique<DummyPublicKeyVerify>("verify0"),
                         keyset_info.key_info(0))
          .status(),
      IsOk());
  ASSERT_THAT(
      public_key_verify_primitive_set
          ->AddPrimitive(absl::make_unique<DummyPublicKeyVerify>("sign1"),
                         keyset_info.key_info(1))
          .status(),
      IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<PublicKeyVerify>::Entry<PublicKeyVerify>*> last =
      public_key_verify_primitive_set->AddPrimitive(
          absl::make_unique<DummyPublicKeyVerify>("sign2"),
          keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(public_key_verify_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t primary_key_id = keyset_info.key_info(2).key_id();

  // Create a PublicKeyVerify primitive to verify a signature.
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> public_key_verify =
      PublicKeyVerifyWrapper().Wrap(std::move(public_key_verify_primitive_set));
  ASSERT_THAT(public_key_verify, IsOkAndHolds(NotNull()));

  // Create a PublicKeySign primitive and sign some data we can verify.
  constexpr absl::string_view message = "This is some message!";
  std::string signature =
      absl::StrCat((*last)->get_identifier(),
                   DummyPublicKeySign("sign2").Sign(message).value());

  // Check that calling Verify triggers a Log() call.
  EXPECT_CALL(*verify_monitoring_client_, Log(primary_key_id, message.size()));
  EXPECT_THAT((*public_key_verify)->Verify(signature, message), IsOk());
}

TEST_F(PublicKeyVerifySetWrapperWithMonitoringTest,
       WrapKeysetWithMonitoringVerifyFailures) {
  // Create a primitive set and fill it with some entries
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto public_key_verify_primitive_set =
      absl::make_unique<PrimitiveSet<PublicKeyVerify>>(kAnnotations);
  ASSERT_THAT(public_key_verify_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingPublicKeyVerify("sign0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(public_key_verify_primitive_set
                  ->AddPrimitive(CreateAlwaysFailingPublicKeyVerify("sign1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<PublicKeyVerify>::Entry<PublicKeyVerify>*> last =
      public_key_verify_primitive_set->AddPrimitive(
          CreateAlwaysFailingPublicKeyVerify("sign2"), keyset_info.key_info(2));
  ASSERT_THAT(last.status(), IsOk());
  ASSERT_THAT(public_key_verify_primitive_set->set_primary(*last), IsOk());

  // Create a PublicKeySign and sign some data we can verify.
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> public_key_verify =
      PublicKeyVerifyWrapper().Wrap(std::move(public_key_verify_primitive_set));
  ASSERT_THAT(public_key_verify, IsOkAndHolds(NotNull()));

  constexpr absl::string_view message = "This is some message!";
  constexpr absl::string_view signature = "This is some invalid signature!";

  // Check that calling Verify triggers a LogFailure() call.
  EXPECT_CALL(*verify_monitoring_client_, LogFailure());
  EXPECT_THAT((*public_key_verify)->Verify(signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
