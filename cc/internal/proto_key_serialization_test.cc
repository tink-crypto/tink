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

#include "tink/internal/proto_key_serialization.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
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
using ::testing::IsFalse;
using ::testing::IsTrue;

class ProtoKeySerializationTest : public ::testing::Test {
 protected:
  bool Equals(ProtoKeySerialization serialization,
              ProtoKeySerialization other) {
    return serialization.EqualsWithPotentialFalseNegatives(other);
  }
};

TEST_F(ProtoKeySerializationTest, CreateWithIdRequirement) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  EXPECT_THAT(serialization->TypeUrl(), Eq("type_url"));
  EXPECT_THAT(serialization->SerializedKeyProto(), Eq(serialized_key));
  EXPECT_THAT(serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(serialization->GetOutputPrefixType(), Eq(OutputPrefixType::TINK));
  EXPECT_THAT(serialization->IdRequirement(), Eq(12345));
  EXPECT_THAT(serialization->ObjectIdentifier(), Eq("type_url"));
}

TEST_F(ProtoKeySerializationTest, CreateWithoutIdRequirement) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::RAW,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization.status(), IsOk());

  EXPECT_THAT(serialization->TypeUrl(), Eq("type_url"));
  EXPECT_THAT(serialization->SerializedKeyProto(), Eq(serialized_key));
  EXPECT_THAT(serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(serialization->GetOutputPrefixType(), Eq(OutputPrefixType::RAW));
  EXPECT_THAT(serialization->IdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(serialization->ObjectIdentifier(), Eq("type_url"));
}

TEST_F(ProtoKeySerializationTest, OutputPrefixIncompatibleWithIdRequirement) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> tink_without_id =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(tink_without_id.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  util::StatusOr<ProtoKeySerialization> raw_with_id =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::RAW,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(raw_with_id.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ProtoKeySerializationTest, Equals) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsTrue());
}

TEST_F(ProtoKeySerializationTest, TypeUrlAndObjectIdentifierNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("different_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoKeySerializationTest, SerializedKeyNotEqual) {
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type_url",
          RestrictedData("serialized_key", InsecureSecretKeyAccess::Get()),
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create(
          "type_url",
          RestrictedData("different_key", InsecureSecretKeyAccess::Get()),
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoKeySerializationTest, KeyMaterialTypeNotEqual) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoKeySerializationTest, OutputPrefixTypeNotEqual) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoKeySerializationTest, IdRequirementNotEqual) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
