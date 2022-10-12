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

#include "tink/internal/legacy_proto_key.h"

#include <tuple>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

class LegacyProtoKeyTest : public ::testing::Test {
 protected:
  // Although this is a friend class, this utility function is necessary to
  // access `ProtoKeySerialization::EqualsWithPotentialFalseNegatives()`
  // since the test fixtures are subclasses that would not have direct access.
  bool Equals(ProtoKeySerialization serialization,
              ProtoKeySerialization other) {
    return serialization.EqualsWithPotentialFalseNegatives(other);
  }
};

TEST_F(LegacyProtoKeyTest, CreateAndSerialization) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetIdRequirement(), Eq(12345));
  EXPECT_THAT(key->GetParameters().HasIdRequirement(), IsTrue());
  EXPECT_THAT(key->Serialization(InsecureSecretKeyAccess::Get()), IsOk());

  util::StatusOr<const ProtoKeySerialization*> key_serialization =
      key->Serialization(InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization.status(), IsOk());
  EXPECT_THAT(Equals(**key_serialization, *serialization), IsTrue());
}

TEST_F(LegacyProtoKeyTest, Equals) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST_F(LegacyProtoKeyTest, TypeUrlNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("other_type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, SerializedKeyNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  RestrictedData other_serialized_key =
      RestrictedData("other_serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", other_serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, KeyMaterialTypeNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key, KeyData::REMOTE,
                                    OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, OutputPrefixTypeNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC,
                                    OutputPrefixType::CRUNCHY,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, IdRequirementNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/6789);
  ASSERT_THAT(other_serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

using AllOutputPrefixTypesTest =
    TestWithParam<std::tuple<OutputPrefixType, absl::optional<int>>>;

INSTANTIATE_TEST_SUITE_P(
    AllOutputPrefixTypesTestSuite, AllOutputPrefixTypesTest,
    Values(std::make_tuple(OutputPrefixType::RAW, absl::nullopt),
           std::make_tuple(OutputPrefixType::TINK, 123),
           std::make_tuple(OutputPrefixType::CRUNCHY, 456),
           std::make_tuple(OutputPrefixType::LEGACY, 789)));

TEST_P(AllOutputPrefixTypesTest, GetIdRequirement) {
  OutputPrefixType output_prefix_type;
  absl::optional<int> id_requirement;
  std::tie(output_prefix_type, id_requirement) = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, output_prefix_type,
                                    id_requirement);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetIdRequirement(), Eq(id_requirement));
}

using AllKeyMaterialTypesTest = TestWithParam<KeyData::KeyMaterialType>;

INSTANTIATE_TEST_SUITE_P(AllKeyMaterialTypesTestSuite, AllKeyMaterialTypesTest,
                         Values(KeyData::SYMMETRIC, KeyData::ASYMMETRIC_PRIVATE,
                                KeyData::ASYMMETRIC_PUBLIC, KeyData::REMOTE));

TEST_P(AllKeyMaterialTypesTest, CreateAndSerializationWithSecretAccessToken) {
  KeyData::KeyMaterialType key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<const ProtoKeySerialization*> key_serialization =
      key->Serialization(InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization.status(), IsOk());
}

using SecretKeyMaterialTypesTest = TestWithParam<KeyData::KeyMaterialType>;

INSTANTIATE_TEST_SUITE_P(SecretKeyMaterialTypesTestSuite,
                         SecretKeyMaterialTypesTest,
                         Values(KeyData::SYMMETRIC,
                                KeyData::ASYMMETRIC_PRIVATE));

TEST_P(SecretKeyMaterialTypesTest, CreateWithoutSecretAccessToken) {
  KeyData::KeyMaterialType key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(SecretKeyMaterialTypesTest, SerializationWithoutSecretAccessToken) {
  KeyData::KeyMaterialType key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  // Must use token for key creation.
  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<const ProtoKeySerialization*> key_serialization =
      key->Serialization(/*token=*/absl::nullopt);
  ASSERT_THAT(key_serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

using NonSecretKeyMaterialTypesTest = TestWithParam<KeyData::KeyMaterialType>;

INSTANTIATE_TEST_SUITE_P(NonSecretKeyMaterialTypesTestSuite,
                         NonSecretKeyMaterialTypesTest,
                         Values(KeyData::ASYMMETRIC_PUBLIC, KeyData::REMOTE));

TEST_P(NonSecretKeyMaterialTypesTest, CreateWithoutSecretAccessToken) {
  KeyData::KeyMaterialType key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key.status(), IsOk());
}

TEST_P(NonSecretKeyMaterialTypesTest, SerializationWithoutSecretAccessToken) {
  KeyData::KeyMaterialType key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  // Must use token for key creation.
  util::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<const ProtoKeySerialization*> key_serialization =
      key->Serialization(/*token=*/absl::nullopt);
  ASSERT_THAT(key_serialization.status(), IsOk());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
