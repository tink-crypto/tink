// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/proto_keyset_format.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_config.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/mac.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::internal::LegacyProtoParameters;
using ::crypto::tink::internal::ProtoParametersSerialization;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::testing::Eq;
using ::testing::Not;

class SerializeKeysetToProtoKeysetFormatTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto status = TinkConfig::Register();
    ASSERT_THAT(status, IsOk());
  }
};

util::StatusOr<LegacyProtoParameters> CmacParameters() {
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(MacKeyTemplates::AesCmac());
  if (!serialization.ok()) return serialization.status();

  return LegacyProtoParameters(*serialization);
}

util::StatusOr<LegacyProtoParameters> EcdsaParameters() {
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(SignatureKeyTemplates::EcdsaP256());
  if (!serialization.ok()) return serialization.status();

  return LegacyProtoParameters(*serialization);
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParseSingleKey) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<SecretData> serialization =
      SerializeKeysetToProtoKeysetFormat(*handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle = ParseKeysetFromProtoKeysetFormat(
      SecretDataAsStringView(*serialization), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(handle->size(), Eq(1));
  ASSERT_THAT(parsed_handle->size(), Eq(1));

  EXPECT_TRUE(*(*handle)[0].GetKey() == *(*parsed_handle)[0].GetKey());
  EXPECT_TRUE((*handle)[0].GetId() == (*parsed_handle)[0].GetId());
  EXPECT_TRUE((*handle)[0].GetStatus() == (*parsed_handle)[0].GetStatus());
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParseMultipleKeys) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
              /*id=*/123))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/125))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kDisabled, /*is_primary=*/true,
              /*id=*/127))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<SecretData> serialization =
      SerializeKeysetToProtoKeysetFormat(*handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle = ParseKeysetFromProtoKeysetFormat(
      SecretDataAsStringView(*serialization), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(handle->size(), Eq(3));
  ASSERT_THAT(parsed_handle->size(), Eq(3));

  EXPECT_TRUE(*(*handle)[0].GetKey() == *(*parsed_handle)[0].GetKey());
  EXPECT_TRUE((*handle)[0].GetId() == (*parsed_handle)[0].GetId());
  EXPECT_TRUE((*handle)[0].GetStatus() == (*parsed_handle)[0].GetStatus());

  EXPECT_TRUE(*(*handle)[1].GetKey() == *(*parsed_handle)[1].GetKey());
  EXPECT_TRUE((*handle)[1].GetId() == (*parsed_handle)[1].GetId());
  EXPECT_TRUE((*handle)[1].GetStatus() == (*parsed_handle)[1].GetStatus());

  EXPECT_TRUE(*(*handle)[2].GetKey() == *(*parsed_handle)[2].GetKey());
  EXPECT_TRUE((*handle)[2].GetId() == (*parsed_handle)[2].GetId());
  EXPECT_TRUE((*handle)[2].GetStatus() == (*parsed_handle)[2].GetStatus());
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeNoAccessFails) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<std::string> serialization =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(*handle);
  ASSERT_THAT(serialization, Not(IsOk()));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, ParseNoAccessFails) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<SecretData> serialization =
      SerializeKeysetToProtoKeysetFormat(*handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(
          SecretDataAsStringView(*serialization));
  ASSERT_THAT(parsed_handle, Not(IsOk()));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, TestVector) {
  std::string serialized_keyset = absl::HexStringToBytes(
      "0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f67"
      "6c652e63727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3513f"
      "5d01759ac1302f7d883f2f4a40025532ee1b11f9e587120410100803180110011895e59b"
      "cc062001");
  crypto::tink::util::StatusOr<KeysetHandle> keyset_handle =
      ParseKeysetFromProtoKeysetFormat(serialized_keyset,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(keyset_handle.status(), IsOk());
  crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac =
      (*keyset_handle).GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  ASSERT_THAT(
      (*mac)->VerifyMac(
          absl::HexStringToBytes("016986f2956092d259136923c6f4323557714ec499"),
          "data"),
      IsOk());
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParsePublicKey) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      EcdsaParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());


  crypto::tink::util::StatusOr<SecretData> serialization1 =
      SerializeKeysetToProtoKeysetFormat(**public_handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization1, IsOk());
  crypto::tink::util::StatusOr<std::string> serialization2 =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(**public_handle);
  ASSERT_THAT(serialization2, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle1 =
      ParseKeysetFromProtoKeysetFormat(SecretDataAsStringView(*serialization1),
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle1, IsOk());
  util::StatusOr<KeysetHandle> parsed_handle2 =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(
          SecretDataAsStringView(*serialization1));
  ASSERT_THAT(parsed_handle2, IsOk());
  util::StatusOr<KeysetHandle> parsed_handle3 =
      ParseKeysetFromProtoKeysetFormat(*serialization2,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle3, IsOk());
  util::StatusOr<KeysetHandle> parsed_handle4 =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(*serialization2);
  ASSERT_THAT(parsed_handle4, IsOk());

  ASSERT_THAT((*public_handle)->size(), Eq(1));
  ASSERT_THAT(parsed_handle1->size(), Eq(1));
  ASSERT_THAT(parsed_handle2->size(), Eq(1));
  ASSERT_THAT(parsed_handle3->size(), Eq(1));
  ASSERT_THAT(parsed_handle4->size(), Eq(1));

  // TODO(b/277791403): Replace with KeysetHandle::Entry equality checks.
  EXPECT_TRUE(*(**public_handle)[0].GetKey() == *(*parsed_handle1)[0].GetKey());
  EXPECT_TRUE(*(**public_handle)[0].GetKey() == *(*parsed_handle2)[0].GetKey());
  EXPECT_TRUE(*(**public_handle)[0].GetKey() == *(*parsed_handle3)[0].GetKey());
  EXPECT_TRUE(*(**public_handle)[0].GetKey() == *(*parsed_handle4)[0].GetKey());

  EXPECT_TRUE((**public_handle)[0].GetId() == (*parsed_handle1)[0].GetId());
  EXPECT_TRUE((**public_handle)[0].GetId() == (*parsed_handle2)[0].GetId());
  EXPECT_TRUE((**public_handle)[0].GetId() == (*parsed_handle3)[0].GetId());
  EXPECT_TRUE((**public_handle)[0].GetId() == (*parsed_handle4)[0].GetId());

  EXPECT_TRUE((**public_handle)[0].GetStatus() ==
              (*parsed_handle1)[0].GetStatus());
  EXPECT_TRUE((**public_handle)[0].GetStatus() ==
              (*parsed_handle2)[0].GetStatus());
  EXPECT_TRUE((**public_handle)[0].GetStatus() ==
              (*parsed_handle3)[0].GetStatus());
  EXPECT_TRUE((**public_handle)[0].GetStatus() ==
              (*parsed_handle4)[0].GetStatus());
}


}  // namespace

}  // namespace tink
}  // namespace crypto
