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

#include "tink/internal/keyset_handle_builder_entry.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/config/tink_config.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Test;

util::StatusOr<LegacyProtoParameters> CreateLegacyProtoParameters() {
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(MacKeyTemplates::AesCmac());
  if (!serialization.ok()) return serialization.status();

  return LegacyProtoParameters(*serialization);
}

TEST(KeysetHandleBuilderEntryTest, Status) {
  util::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(absl::make_unique<LegacyProtoParameters>(*parameters));

  entry.SetStatus(KeyStatus::kEnabled);
  EXPECT_THAT(entry.GetStatus(), KeyStatus::kEnabled);

  entry.SetStatus(KeyStatus::kDisabled);
  EXPECT_THAT(entry.GetStatus(), KeyStatus::kDisabled);

  entry.SetStatus(KeyStatus::kDestroyed);
  EXPECT_THAT(entry.GetStatus(), KeyStatus::kDestroyed);
}

TEST(KeysetHandleBuilderEntryTest, IdStrategy) {
  util::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(absl::make_unique<LegacyProtoParameters>(*parameters));

  entry.SetFixedId(123);
  EXPECT_THAT(entry.GetKeyIdStrategyEnum(), KeyIdStrategyEnum::kFixedId);
  EXPECT_THAT(entry.GetKeyIdStrategy().strategy, KeyIdStrategyEnum::kFixedId);
  EXPECT_THAT(entry.GetKeyIdStrategy().id_requirement, 123);
  EXPECT_THAT(entry.GetKeyIdRequirement(), 123);

  entry.SetRandomId();
  EXPECT_THAT(entry.GetKeyIdStrategyEnum(), KeyIdStrategyEnum::kRandomId);
  EXPECT_THAT(entry.GetKeyIdStrategy().strategy, KeyIdStrategyEnum::kRandomId);
  EXPECT_THAT(entry.GetKeyIdStrategy().id_requirement, absl::nullopt);
  EXPECT_THAT(entry.GetKeyIdRequirement(), absl::nullopt);
}

TEST(KeysetHandleBuilderEntryTest, Primary) {
  util::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(absl::make_unique<LegacyProtoParameters>(*parameters));

  entry.SetPrimary();
  EXPECT_THAT(entry.IsPrimary(), IsTrue());

  entry.UnsetPrimary();
  EXPECT_THAT(entry.IsPrimary(), IsFalse());
}

class CreateKeysetKeyTest : public Test {
 protected:
  void SetUp() override { ASSERT_THAT(TinkConfig::Register(), IsOk()); }
};

TEST_F(CreateKeysetKeyTest, CreateKeysetKeyFromParameters) {
  util::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(absl::make_unique<LegacyProtoParameters>(*parameters));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  util::StatusOr<Keyset::Key> keyset_key = entry.CreateKeysetKey(/*id=*/123);
  ASSERT_THAT(keyset_key, IsOk());

  EXPECT_THAT(keyset_key->status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT(keyset_key->key_id(), Eq(123));
  EXPECT_THAT(
      keyset_key->output_prefix_type(),
      Eq(parameters->Serialization().GetKeyTemplate().output_prefix_type()));
  EXPECT_THAT(keyset_key->key_data().type_url(),
              Eq(parameters->Serialization().GetKeyTemplate().type_url()));
}

TEST_F(CreateKeysetKeyTest, CreateKeysetKeyFromParametersWithDifferentKeyId) {
  util::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(absl::make_unique<LegacyProtoParameters>(*parameters));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  util::StatusOr<Keyset::Key> keyset_key = entry.CreateKeysetKey(/*id=*/456);
  EXPECT_THAT(keyset_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(CreateKeysetKeyTest, CreateKeysetKeyFromKey) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  KeyEntry entry = KeyEntry(absl::make_unique<LegacyProtoKey>(*key));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  util::StatusOr<Keyset::Key> keyset_key = entry.CreateKeysetKey(/*id=*/123);
  ASSERT_THAT(keyset_key, IsOk());

  EXPECT_THAT(keyset_key->status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT(keyset_key->key_id(), Eq(123));
  EXPECT_THAT(keyset_key->output_prefix_type(), OutputPrefixType::TINK);
  EXPECT_THAT(keyset_key->key_data().type_url(), Eq("type_url"));
  EXPECT_THAT(keyset_key->key_data().key_material_type(),
              Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(keyset_key->key_data().value(), Eq("serialized_key"));
}

TEST_F(CreateKeysetKeyTest, CreateKeysetKeyFromKeyWithDifferentEntryKeyId) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  KeyEntry entry = KeyEntry(absl::make_unique<LegacyProtoKey>(*key));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  util::StatusOr<Keyset::Key> keyset_key = entry.CreateKeysetKey(/*id=*/456);
  EXPECT_THAT(keyset_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(CreateKeysetKeyTest,
       CreateKeysetKeyFromKeyWithDifferentSerializationKeyId) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  KeyEntry entry = KeyEntry(absl::make_unique<LegacyProtoKey>(*key));
  entry.SetStatus(KeyStatus::kEnabled);
  util::StatusOr<Keyset::Key> keyset_key = entry.CreateKeysetKey(/*id=*/456);
  EXPECT_THAT(keyset_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
