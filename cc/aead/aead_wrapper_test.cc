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

#include "tink/aead/aead_wrapper.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/mock_aead.h"
#include "tink/crypto_format.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/monitoring/monitoring_client_mocks.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::ByMove;
using ::testing::HasSubstr;
using ::testing::IsNull;
using ::testing::IsSubstring;
using ::testing::Not;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::Test;

void PopulateKeyInfo(KeysetInfo::KeyInfo* key_info, uint32_t key_id,
                     OutputPrefixType out_prefix_type, KeyStatusType status) {
  key_info->set_output_prefix_type(out_prefix_type);
  key_info->set_key_id(key_id);
  key_info->set_status(status);
}

// Creates a test keyset info object.
KeysetInfo CreateTestKeysetInfo() {
  KeysetInfo keyset_info;
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/1234543,
                  OutputPrefixType::TINK,
                  /*status=*/KeyStatusType::ENABLED);
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/726329,
                  OutputPrefixType::LEGACY,
                  /*status=*/KeyStatusType::ENABLED);
  PopulateKeyInfo(keyset_info.add_key_info(), /*key_id=*/7213743,
                  OutputPrefixType::TINK,
                  /*status=*/KeyStatusType::ENABLED);
  return keyset_info;
}

TEST(AeadSetWrapperTest, WrapNullptr) {
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead = wrapper.Wrap(nullptr);
  EXPECT_THAT(aead, Not(IsOk()));
  EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInternal));
  EXPECT_PRED_FORMAT2(IsSubstring, "non-NULL",
                      std::string(aead.status().message()));
}

TEST(AeadSetWrapperTest, WrapEmpty) {
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead =
      wrapper.Wrap(absl::make_unique<PrimitiveSet<Aead>>());
  EXPECT_THAT(aead, Not(IsOk()));
  EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "no primary",
                      std::string(aead.status().message()));
}

TEST(AeadSetWrapperTest, Basic) {
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  std::string aead_name_0 = "aead0";
  std::string aead_name_1 = "aead1";
  std::string aead_name_2 = "aead2";
  auto aead_set = absl::make_unique<PrimitiveSet<Aead>>();
  std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>(aead_name_0);
  util::StatusOr<PrimitiveSet<Aead>::Entry<Aead>*> aead_entry =
      aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(0));
  EXPECT_THAT(aead_entry, IsOk());
  aead = absl::make_unique<DummyAead>(aead_name_1);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(1));
  EXPECT_THAT(aead_entry, IsOk());
  aead = absl::make_unique<DummyAead>(aead_name_2);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(2));
  EXPECT_THAT(aead_entry, IsOk());
  // The last key is the primary.
  EXPECT_THAT(aead_set->set_primary(*aead_entry), IsOk());

  // Wrap aead_set and test the resulting Aead.
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead_result =
      wrapper.Wrap(std::move(aead_set));
  EXPECT_THAT(aead_result, IsOk());
  aead = std::move(*aead_result);
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";

  util::StatusOr<std::string> encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_THAT(encrypt_result, IsOk());
  std::string ciphertext = *encrypt_result;
  EXPECT_PRED_FORMAT2(testing::IsSubstring, aead_name_2, ciphertext);

  util::StatusOr<std::string> resulting_plaintext =
      aead->Decrypt(ciphertext, aad);
  EXPECT_THAT(resulting_plaintext, IsOk());
  EXPECT_EQ(*resulting_plaintext, plaintext);

  resulting_plaintext = aead->Decrypt("some bad ciphertext", aad);
  EXPECT_THAT(resulting_plaintext, Not(IsOk()));
  EXPECT_THAT(resulting_plaintext.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "decryption failed",
                      std::string(resulting_plaintext.status().message()));
}

TEST(AeadSetWrapperTest, DecryptNonPrimary) {
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  std::string aead_name_0 = "aead0";
  std::string aead_name_1 = "aead1";
  std::string aead_name_2 = "aead2";
  std::unique_ptr<PrimitiveSet<Aead>> aead_set(new PrimitiveSet<Aead>());
  std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>(aead_name_0);

  // Encrypt some message with the first aead.s
  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  util::StatusOr<std::string> ciphertext = aead->Encrypt(plaintext, aad);
  EXPECT_THAT(ciphertext, IsOk());
  util::StatusOr<PrimitiveSet<Aead>::Entry<Aead>*> aead_entry =
      aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(0));
  ASSERT_THAT(aead_entry, IsOk());
  EXPECT_THAT(aead_set->set_primary(*aead_entry), IsOk());

  // The complete ciphertext is of the form: | key_id | ciphertext |.
  std::string complete_ciphertext =
      absl::StrCat(aead_set->get_primary()->get_identifier(), *ciphertext);

  aead = absl::make_unique<DummyAead>(aead_name_1);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(1));
  EXPECT_THAT(aead_entry, IsOk());
  aead = absl::make_unique<DummyAead>(aead_name_2);
  aead_entry = aead_set->AddPrimitive(std::move(aead), keyset_info.key_info(2));
  EXPECT_THAT(aead_entry, IsOk());
  // The last key is the primary.
  EXPECT_THAT(aead_set->set_primary(*aead_entry), IsOk());

  // Wrap aead_set and test the resulting Aead.
  AeadWrapper wrapper;
  util::StatusOr<std::unique_ptr<Aead>> aead_wrapped =
      wrapper.Wrap(std::move(aead_set));
  EXPECT_THAT(aead_wrapped, IsOk());
  aead = std::move(*aead_wrapped);
  EXPECT_THAT(complete_ciphertext, HasSubstr(aead_name_0));

  // Primary key is different from the one we used to encrypt. This
  // should still be decryptable as we have the correct key in the set.
  util::StatusOr<std::string> decrypted_plaintext =
      aead->Decrypt(complete_ciphertext, aad);
  EXPECT_THAT(decrypted_plaintext, IsOk());
}

// Tests with monitoring enabled.
class AeadSetWrapperTestWithMonitoring : public Test {
 protected:
  // Perform some common initialization: reset the global registry, set expected
  // calls for the mock monitoring factory and the returned clients.
  void SetUp() override {
    Registry::Reset();
    auto monitoring_client_factory =
        absl::make_unique<MockMonitoringClientFactory>();

    auto encryption_monitoring_client =
        absl::make_unique<StrictMock<MockMonitoringClient>>();
    encryption_monitoring_client_ptr_ = encryption_monitoring_client.get();
    auto decryption_monitoring_client =
        absl::make_unique<StrictMock<MockMonitoringClient>>();
    decryption_monitoring_client_ptr_ = decryption_monitoring_client.get();

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
  void TearDown() override { Registry::Reset(); }

  MockMonitoringClient* encryption_monitoring_client_ptr_;
  MockMonitoringClient* decryption_monitoring_client_ptr_;
};

// Test that successful encrypt/decrypt operations are logged.
TEST_F(AeadSetWrapperTestWithMonitoring,
       WrapKeysetWithMonitoringEncryptDecryptSuccess) {
  // Populate a primitive set.
  KeysetInfo keyset_info = CreateTestKeysetInfo();
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};
  auto aead_primitive_set = absl::make_unique<PrimitiveSet<Aead>>(kAnnotations);
  ASSERT_THAT(aead_primitive_set
                  ->AddPrimitive(absl::make_unique<DummyAead>("aead0"),
                                 keyset_info.key_info(0))
                  .status(),
              IsOk());
  ASSERT_THAT(aead_primitive_set
                  ->AddPrimitive(absl::make_unique<DummyAead>("aead1"),
                                 keyset_info.key_info(1))
                  .status(),
              IsOk());
  // Set the last as primary.
  util::StatusOr<PrimitiveSet<Aead>::Entry<Aead>*> last =
      aead_primitive_set->AddPrimitive(absl::make_unique<DummyAead>("aead2"),
                                       keyset_info.key_info(2));
  ASSERT_THAT(last, IsOk());
  ASSERT_THAT(aead_primitive_set->set_primary(*last), IsOk());
  // Record the ID of the primary key.
  const uint32_t kPrimaryKeyId = keyset_info.key_info(2).key_id();

  util::StatusOr<std::unique_ptr<Aead>> aead =
      AeadWrapper().Wrap(std::move(aead_primitive_set));
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "This is some plaintext!";
  constexpr absl::string_view kAssociatedData = "Some associated data!";
  EXPECT_CALL(*encryption_monitoring_client_ptr_,
              Log(kPrimaryKeyId, kPlaintext.size()));
  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());

  // In the log expect the size of the ciphertext without the non-raw prefix.
  auto raw_ciphertext =
      absl::string_view(*ciphertext).substr(CryptoFormat::kNonRawPrefixSize);
  EXPECT_CALL(*decryption_monitoring_client_ptr_,
              Log(kPrimaryKeyId, raw_ciphertext.size()));
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData), IsOk());
}

// Test that monitoring logs encryption and decryption failures correctly.
TEST_F(AeadSetWrapperTestWithMonitoring,
       WrapKeysetWithMonitoringEncryptDecryptFailures) {
  // Populate a primitive set.
  KeysetInfo keyset_info = CreateTestKeysetInfo();

  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}};

  auto aead_primitive_set = absl::make_unique<PrimitiveSet<Aead>>(kAnnotations);

  // Assume encryption and decryption always fail.
  auto mock_aead = absl::make_unique<MockAead>();
  constexpr absl::string_view kPlaintext = "A plaintext!!";
  constexpr absl::string_view kCiphertext = "A ciphertext!";
  constexpr absl::string_view kAssociatedData = "Some associated data!";
  ON_CALL(*mock_aead, Encrypt(kPlaintext, kAssociatedData))
      .WillByDefault(Return(util::Status(absl::StatusCode::kInternal,
                                         "Oh no encryption failed :(!")));
  ON_CALL(*mock_aead, Decrypt(kCiphertext, kAssociatedData))
      .WillByDefault(Return(util::Status(absl::StatusCode::kInternal,
                                         "Oh no decryption failed :(!")));

  util::StatusOr<PrimitiveSet<Aead>::Entry<Aead>*> primary =
      aead_primitive_set->AddPrimitive(std::move(mock_aead),
                                       keyset_info.key_info(2));
  ASSERT_THAT(primary, IsOk());
  // Set the only primitive as primary.
  ASSERT_THAT(aead_primitive_set->set_primary(*primary), IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      AeadWrapper().Wrap(std::move(aead_primitive_set));
  ASSERT_THAT(aead, IsOk());

  // Expect encryption failure gets logged.
  EXPECT_CALL(*encryption_monitoring_client_ptr_, LogFailure());
  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  EXPECT_THAT(ciphertext, Not(IsOk()));

  // We must prepend the identifier to the ciphertext to make sure our mock gets
  // called.
  util::StatusOr<std::string> key_identifier =
      CryptoFormat::GetOutputPrefix(keyset_info.key_info(2));
  ASSERT_THAT(key_identifier, IsOk());
  std::string ciphertext_with_key_id =
      absl::StrCat(*key_identifier, kCiphertext);

  // Expect decryption failure gets logged.
  EXPECT_CALL(*decryption_monitoring_client_ptr_, LogFailure());
  EXPECT_THAT(
      (*aead)->Decrypt(ciphertext_with_key_id, kAssociatedData).status(),
      Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
