// Copyright 2022 Google LLC
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

#include "tink/keyset_handle_builder.h"

#include <memory>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_config.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/key_status.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_cmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacKey;
using ::google::crypto::tink::AesCmacParams;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::SizeIs;
using ::testing::Test;

class KeysetHandleBuilderTest : public Test {
 protected:
  void SetUp() override {
    util::Status status = TinkConfig::Register();
    ASSERT_TRUE(status.ok()) << status;
  }
};

using KeysetHandleBuilderDeathTest = KeysetHandleBuilderTest;

util::StatusOr<internal::LegacyProtoParameters> CreateLegacyProtoParameters(
    KeyTemplate key_template) {
  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(key_template);
  if (!serialization.ok()) return serialization.status();

  return internal::LegacyProtoParameters(*serialization);
}

TEST_F(KeysetHandleBuilderTest, BuildWithSingleKey) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  EXPECT_THAT(*handle, SizeIs(1));

  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[0].GetKey().GetParameters().HasIdRequirement(),
              IsTrue());
}

TEST_F(KeysetHandleBuilderTest, BuildWithMultipleKeys) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDisabled,
          /*is_primary=*/false, /*id=*/789);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build();
  ASSERT_THAT(handle.status(), IsOk());
  EXPECT_THAT(*handle, SizeIs(3));

  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[0].GetKey().GetParameters().HasIdRequirement(),
              IsTrue());

  EXPECT_THAT((*handle)[1].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[1].GetId(), Eq(456));
  EXPECT_THAT((*handle)[1].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[1].GetKey().GetParameters().HasIdRequirement(),
              IsTrue());

  EXPECT_THAT((*handle)[2].GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT((*handle)[2].GetId(), Eq(789));
  EXPECT_THAT((*handle)[2].IsPrimary(), IsFalse());
  EXPECT_THAT((*handle)[2].GetKey().GetParameters().HasIdRequirement(),
              IsTrue());
}

TEST_F(KeysetHandleBuilderTest, BuildCopy) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDisabled,
          /*is_primary=*/false, /*id=*/789);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build();
  ASSERT_THAT(handle.status(), IsOk());

  util::StatusOr<KeysetHandle> copy = KeysetHandleBuilder(*handle).Build();
  ASSERT_THAT(copy.status(), IsOk());
  EXPECT_THAT(copy->size(), Eq(3));

  EXPECT_THAT((*copy)[0].GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT((*copy)[0].GetId(), Eq(123));
  EXPECT_THAT((*copy)[0].IsPrimary(), IsFalse());
  EXPECT_THAT((*copy)[0].GetKey().GetParameters().HasIdRequirement(), IsTrue());

  EXPECT_THAT((*copy)[1].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*copy)[1].GetId(), Eq(456));
  EXPECT_THAT((*copy)[1].IsPrimary(), IsTrue());
  EXPECT_THAT((*copy)[1].GetKey().GetParameters().HasIdRequirement(), IsTrue());

  EXPECT_THAT((*copy)[2].GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT((*copy)[2].GetId(), Eq(789));
  EXPECT_THAT((*copy)[2].IsPrimary(), IsFalse());
  EXPECT_THAT((*copy)[2].GetKey().GetParameters().HasIdRequirement(), IsTrue());
}

TEST_F(KeysetHandleBuilderTest, IsPrimary) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*parameters,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/false,
                                                           /*id=*/123);
  EXPECT_THAT(entry.IsPrimary(), IsFalse());

  entry.SetPrimary();
  EXPECT_THAT(entry.IsPrimary(), IsTrue());
}

TEST_F(KeysetHandleBuilderTest, SetAndGetStatus) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/123);

  entry.SetStatus(KeyStatus::kDisabled);
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kDisabled));
  entry.SetStatus(KeyStatus::kEnabled);
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kEnabled));
  entry.SetStatus(KeyStatus::kDestroyed);
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kDestroyed));
}

TEST_F(KeysetHandleBuilderTest, BuildWithRandomId) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry primary =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  KeysetHandleBuilder builder;
  builder.AddEntry(std::move(primary));

  int num_non_primary_entries = 1 << 16;
  for (int i = 0; i < num_non_primary_entries; ++i) {
    KeysetHandleBuilder::Entry non_primary =
        KeysetHandleBuilder::Entry::CreateFromCopyableParams(
            *parameters, KeyStatus::kEnabled, /*is_primary=*/false);
    builder.AddEntry(std::move(non_primary));
  }

  util::StatusOr<KeysetHandle> handle = builder.Build();
  ASSERT_THAT(handle.status(), IsOk());

  std::set<int> ids;
  for (int i = 0; i < handle->size(); ++i) {
    ids.insert((*handle)[i].GetId());
  }
  EXPECT_THAT(ids, SizeIs(num_non_primary_entries + 1));
}

TEST_F(KeysetHandleBuilderTest, BuildWithRandomIdAfterFixedId) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry fixed =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder::Entry random =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(fixed))
                                            .AddEntry(std::move(random))
                                            .Build();
  ASSERT_THAT(handle.status(), IsOk());

  EXPECT_THAT(*handle, SizeIs(2));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
}

TEST_F(KeysetHandleBuilderTest, BuildWithFixedIdAfterRandomIdFails) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry random =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false);

  KeysetHandleBuilder::Entry fixed =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(random))
                                            .AddEntry(std::move(fixed))
                                            .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderDeathTest, AddEntryToAnotherBuilderCrashes) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder builder0;
  builder0.AddEntry(std::move(entry));
  KeysetHandleBuilder builder1;
  EXPECT_DEATH_IF_SUPPORTED(
      builder1.AddEntry(std::move(builder0[0])),
      "Keyset handle builder entry already added to a builder.");
}

TEST_F(KeysetHandleBuilderDeathTest, ReAddEntryToSameBuilderCrashes) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder builder;
  builder.AddEntry(std::move(entry));
  EXPECT_DEATH_IF_SUPPORTED(
      builder.AddEntry(std::move(builder[0])),
      "Keyset handle builder entry already added to a builder.");
}

TEST_F(KeysetHandleBuilderDeathTest,
       AddDereferencedEntryToAnotherBuilderCrashes) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  KeysetHandleBuilder builder0;
  builder0.AddEntry(std::move(entry));
  KeysetHandleBuilder builder1;
  EXPECT_DEATH_IF_SUPPORTED(
      builder1.AddEntry(std::move(*&(builder0[0]))),
      "Keyset handle builder entry already added to a builder.");
}

TEST_F(KeysetHandleBuilderTest, RemoveEntry) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false, /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/456);

  util::StatusOr<KeysetHandle> handle0 = KeysetHandleBuilder()
                                             .AddEntry(std::move(entry0))
                                             .AddEntry(std::move(entry1))
                                             .Build();
  ASSERT_THAT(handle0.status(), IsOk());
  ASSERT_THAT(*handle0, SizeIs(2));

  util::StatusOr<KeysetHandle> handle1 =
      KeysetHandleBuilder(*handle0).RemoveEntry(0).Build();
  ASSERT_THAT(handle1.status(), IsOk());
  ASSERT_THAT(*handle1, SizeIs(1));

  EXPECT_THAT((*handle1)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle1)[0].GetId(), Eq(456));
  EXPECT_THAT((*handle1)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle1)[0].GetKey().GetParameters().HasIdRequirement(),
              IsTrue());
}

TEST_F(KeysetHandleBuilderDeathTest, RemoveOutofRangeIndexEntryCrashes) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true, /*id=*/123);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_DEATH_IF_SUPPORTED(
      KeysetHandleBuilder(*handle).RemoveEntry(1),
      "Keyset handle builder entry removal index out of range.");
}

TEST_F(KeysetHandleBuilderTest, Size) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kDestroyed,
          /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/456);

  KeysetHandleBuilder builder;
  ASSERT_THAT(builder, SizeIs(0));
  builder.AddEntry(std::move(entry0));
  ASSERT_THAT(builder, SizeIs(1));
  builder.AddEntry(std::move(entry1));
  EXPECT_THAT(builder, SizeIs(2));
}

TEST_F(KeysetHandleBuilderTest, NoPrimaryFails) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/456);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderTest, RemovePrimaryFails) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
          /*id=*/456);

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .RemoveEntry(0)
                                            .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleBuilderTest, AddPrimaryClearsOtherPrimary) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder builder;
  builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
      *parameters, KeyStatus::kEnabled,
      /*is_primary=*/true,
      /*id=*/123));
  builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
      *parameters, KeyStatus::kEnabled,
      /*is_primary=*/true,
      /*id=*/456));

  ASSERT_THAT(builder[0].IsPrimary(), IsFalse());
  ASSERT_THAT(builder[1].IsPrimary(), IsTrue());
}

TEST_F(KeysetHandleBuilderTest, NoIdStrategySucceeds) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle, IsOk());
}

TEST_F(KeysetHandleBuilderTest, DuplicateId) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled,
              /*is_primary=*/true,
              /*id=*/123))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled,
              /*is_primary=*/false,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromKey) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::DISABLED,
             KeyData::SYMMETRIC, &keyset);

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          key.key_data().type_url(),
          RestrictedData(key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          key.key_data().key_material_type(), key.output_prefix_type(),
          key.key_id());

  util::StatusOr<internal::LegacyProtoKey> proto_key =
      internal::LegacyProtoKey::Create(*serialization,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key.status(), IsOk());

  KeysetHandleBuilder::Entry entry = KeysetHandleBuilder::Entry::CreateFromKey(
      absl::make_unique<internal::LegacyProtoKey>(std::move(*proto_key)),
      KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromCopyableKey) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::DISABLED,
             KeyData::SYMMETRIC, &keyset);

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          key.key_data().type_url(),
          RestrictedData(key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          key.key_data().key_material_type(), key.output_prefix_type(),
          key.key_id());

  util::StatusOr<internal::LegacyProtoKey> proto_key =
      internal::LegacyProtoKey::Create(*serialization,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *proto_key, KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromParameters) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromParams(
          absl::make_unique<internal::LegacyProtoParameters>(*parameters),
          KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, CreateBuilderEntryFromCopyableParameters) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
}

TEST_F(KeysetHandleBuilderTest, UsePrimitiveFromLegacyProtoParams) {
  util::StatusOr<internal::LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters(MacKeyTemplates::AesCmac());
  ASSERT_THAT(parameters.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());

  util::StatusOr<std::unique_ptr<Mac>> mac = handle->GetPrimitive<Mac>();
  ASSERT_THAT(mac.status(), IsOk());
  util::StatusOr<std::string> tag = (*mac)->ComputeMac("some input");
  ASSERT_THAT(tag.status(), IsOk());
  util::Status verified = (*mac)->VerifyMac(*tag, "some input");
  EXPECT_THAT(verified, IsOk());
}

TEST_F(KeysetHandleBuilderTest, UsePrimitiveFromLegacyProtoKey) {
  AesCmacParams params;
  params.set_tag_size(16);
  AesCmacKey key;
  *key.mutable_params() = params;
  key.set_version(0);
  key.set_key_value(subtle::Random::GetRandomBytes(32));

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          RestrictedData(key.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<internal::LegacyProtoKey> proto_key =
      internal::LegacyProtoKey::Create(*serialization,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(proto_key.status(), IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *proto_key, KeyStatus::kEnabled, /*is_primary=*/true);

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());

  util::StatusOr<std::unique_ptr<Mac>> mac = handle->GetPrimitive<Mac>();
  ASSERT_THAT(mac.status(), IsOk());
  util::StatusOr<std::string> tag = (*mac)->ComputeMac("some input");
  ASSERT_THAT(tag.status(), IsOk());
  util::Status verified = (*mac)->VerifyMac(*tag, "some input");
  EXPECT_THAT(verified, IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
