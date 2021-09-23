// Copyright 2017 Google LLC
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
#include "tink/keyset_manager.h"

#include "gtest/gtest.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/config.h"
#include "tink/keyset_handle.h"
#include "tink/util/test_keyset_handle.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::TestKeysetHandle;

using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

class KeysetManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto status = AeadConfig::Register();
    ASSERT_TRUE(status.ok()) << status;
  }
  void TearDown() override {}
};

TEST_F(KeysetManagerTest, testBasicOperations) {
  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  KeyTemplate key_template;
  key_template.set_type_url(AesGcmKeyManager().get_key_type());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_value(key_format.SerializeAsString());

  // Create a keyset manager with a single key.
  auto new_result = KeysetManager::New(key_template);
  EXPECT_TRUE(new_result.ok()) << new_result.status();
  auto keyset_manager = std::move(new_result.ValueOrDie());
  EXPECT_EQ(1, keyset_manager->KeyCount());

  // Verify the keyset.
  auto keyset =
      TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(1, keyset.key().size());
  auto key_id_0 = keyset.key(0).key_id();
  EXPECT_EQ(key_id_0, keyset.primary_key_id());
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(0).status());
  EXPECT_EQ(OutputPrefixType::TINK, keyset.key(0).output_prefix_type());
  EXPECT_EQ(AesGcmKeyManager().get_key_type(),
            keyset.key(0).key_data().type_url());
  EXPECT_EQ(KeyData::SYMMETRIC, keyset.key(0).key_data().key_material_type());

  // Add another key.
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  auto add_result = keyset_manager->Add(key_template);
  EXPECT_TRUE(add_result.ok()) << add_result.status();
  EXPECT_EQ(2, keyset_manager->KeyCount());
  auto key_id_1 = add_result.ValueOrDie();
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(2, keyset.key().size());
  EXPECT_EQ(key_id_0, keyset.primary_key_id());
  EXPECT_FALSE(keyset.key(0).key_data().value() ==
               keyset.key(1).key_data().value());
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(1).status());
  EXPECT_EQ(OutputPrefixType::RAW, keyset.key(1).output_prefix_type());
  EXPECT_EQ(AesGcmKeyManager().get_key_type(),
            keyset.key(1).key_data().type_url());
  EXPECT_EQ(KeyData::SYMMETRIC, keyset.key(1).key_data().key_material_type());

  // And another one, via rotation.
  key_template.set_output_prefix_type(OutputPrefixType::LEGACY);
  auto rotate_result = keyset_manager->Rotate(key_template);
  EXPECT_TRUE(rotate_result.ok()) << add_result.status();
  EXPECT_EQ(3, keyset_manager->KeyCount());
  auto key_id_2 = rotate_result.ValueOrDie();
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(3, keyset.key().size());
  EXPECT_EQ(key_id_2, keyset.primary_key_id());
  EXPECT_FALSE(keyset.key(0).key_data().value() ==
               keyset.key(2).key_data().value());
  EXPECT_FALSE(keyset.key(1).key_data().value() ==
               keyset.key(2).key_data().value());
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(2).status());
  EXPECT_EQ(OutputPrefixType::LEGACY, keyset.key(2).output_prefix_type());
  EXPECT_EQ(AesGcmKeyManager().get_key_type(),
            keyset.key(2).key_data().type_url());
  EXPECT_EQ(KeyData::SYMMETRIC, keyset.key(2).key_data().key_material_type());

  // Change the primary.
  auto status = keyset_manager->SetPrimary(key_id_1);
  EXPECT_TRUE(status.ok()) << status;
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(3, keyset.key().size());
  EXPECT_EQ(3, keyset_manager->KeyCount());
  EXPECT_EQ(key_id_1, keyset.primary_key_id());

  // Clone a keyset via the manager, and check equality.
  auto keyset_manager_2 = std::move(
      KeysetManager::New(*keyset_manager->GetKeysetHandle()).ValueOrDie());
  auto keyset_2 =
      TestKeysetHandle::GetKeyset(*(keyset_manager_2->GetKeysetHandle()));
  EXPECT_EQ(keyset.SerializeAsString(), keyset_2.SerializeAsString());

  // Disable a key, and try to set it as primary.
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(2).status());
  status = keyset_manager->Disable(key_id_2);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(3, keyset_manager->KeyCount());
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(KeyStatusType::DISABLED, keyset.key(2).status());

  status = keyset_manager->SetPrimary(key_id_2);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be ENABLED",
                      status.error_message());
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(key_id_1, keyset.primary_key_id());

  // Enable ENABLED key, disable a DISABLED one.
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(1).status());
  status = keyset_manager->Enable(key_id_1);
  EXPECT_TRUE(status.ok()) << status;
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(1).status());

  EXPECT_EQ(KeyStatusType::DISABLED, keyset.key(2).status());
  status = keyset_manager->Disable(key_id_2);
  EXPECT_TRUE(status.ok()) << status;
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(KeyStatusType::DISABLED, keyset.key(2).status());

  // Enable the disabled key, then destroy it, and try to re-enable.
  EXPECT_EQ(KeyStatusType::DISABLED, keyset.key(2).status());
  status = keyset_manager->Enable(key_id_2);
  EXPECT_TRUE(status.ok()) << status;
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(KeyStatusType::ENABLED, keyset.key(2).status());
  EXPECT_TRUE(keyset.key(2).has_key_data());

  status = keyset_manager->Destroy(key_id_2);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(3, keyset_manager->KeyCount());
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(KeyStatusType::DESTROYED, keyset.key(2).status());
  EXPECT_FALSE(keyset.key(2).has_key_data());

  status = keyset_manager->Enable(key_id_2);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Cannot enable",
                      status.error_message());
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(KeyStatusType::DESTROYED, keyset.key(2).status());
  EXPECT_EQ(key_id_1, keyset.primary_key_id());

  // Delete the destroyed key, then try to destroy and delete it again.
  status = keyset_manager->Delete(key_id_2);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(2, keyset_manager->KeyCount());
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));

  EXPECT_EQ(2, keyset.key().size());

  status = keyset_manager->Destroy(key_id_2);
  EXPECT_EQ(absl::StatusCode::kNotFound, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No key with key_id",
                      status.error_message());

  status = keyset_manager->Delete(key_id_2);
  EXPECT_EQ(absl::StatusCode::kNotFound, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No key with key_id",
                      status.error_message());

  // Try disabling/destroying/deleting the primary key.
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));

  EXPECT_EQ(key_id_1, keyset.primary_key_id());

  status = keyset_manager->Disable(key_id_1);
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Cannot disable primary",
                      status.error_message());

  status = keyset_manager->Destroy(key_id_1);
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Cannot destroy primary",
                      status.error_message());

  status = keyset_manager->Delete(key_id_1);
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "Cannot delete primary",
                      status.error_message());

  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(key_id_1, keyset.primary_key_id());

  // Delete the first key, then try to set it as primary.
  status = keyset_manager->Delete(key_id_0);
  EXPECT_TRUE(status.ok()) << status;
  keyset = TestKeysetHandle::GetKeyset(*(keyset_manager->GetKeysetHandle()));
  EXPECT_EQ(1, keyset.key().size());
  EXPECT_EQ(key_id_1, keyset.key(0).key_id());

  status = keyset_manager->SetPrimary(key_id_0);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kNotFound, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No key with key_id",
                      status.error_message());
  EXPECT_EQ(1, keyset_manager->KeyCount());
}

}  // namespace tink
}  // namespace crypto
