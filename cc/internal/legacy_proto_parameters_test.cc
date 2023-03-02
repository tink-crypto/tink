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

#include "tink/internal/legacy_proto_parameters.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestProto;
using ::testing::IsFalse;
using ::testing::IsTrue;

class LegacyProtoParametersTest : public ::testing::Test {
 protected:
  // Although this is a friend class, this utility function is necessary to
  // access `ProtoParametersSerialization::EqualsWithPotentialFalseNegatives()`
  // since the test fixtures are subclasses that would not have direct access.
  bool Equals(ProtoParametersSerialization serialization,
              ProtoParametersSerialization other) {
    return serialization.EqualsWithPotentialFalseNegatives(other);
  }
};

TEST_F(LegacyProtoParametersTest, CreateWithIdRequirement) {
  TestProto test_proto;
  test_proto.set_num(12345);
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::TINK,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  LegacyProtoParameters parameters(*serialization);

  EXPECT_THAT(parameters.HasIdRequirement(), IsTrue());
  EXPECT_THAT(Equals(*serialization, parameters.Serialization()), IsTrue());
}

TEST_F(LegacyProtoParametersTest, CreateWithoutIdRequirement) {
  TestProto test_proto;
  test_proto.set_num(12345);
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  LegacyProtoParameters parameters(*serialization);

  EXPECT_THAT(parameters.HasIdRequirement(), IsFalse());
  EXPECT_THAT(Equals(*serialization, parameters.Serialization()), IsTrue());
}

TEST_F(LegacyProtoParametersTest, Equals) {
  TestProto test_proto;
  test_proto.set_num(12345);

  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  LegacyProtoParameters parameters(*serialization);
  LegacyProtoParameters other_parameters(*other_serialization);

  EXPECT_TRUE(parameters == other_parameters);
  EXPECT_TRUE(other_parameters == parameters);
  EXPECT_FALSE(parameters != other_parameters);
  EXPECT_FALSE(other_parameters != parameters);
}

TEST_F(LegacyProtoParametersTest, TypeUrlNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);

  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("other_type_url",
                                           OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  LegacyProtoParameters parameters(*serialization);
  LegacyProtoParameters other_parameters(*other_serialization);

  EXPECT_TRUE(parameters != other_parameters);
  EXPECT_TRUE(other_parameters != parameters);
  EXPECT_FALSE(parameters == other_parameters);
  EXPECT_FALSE(other_parameters == parameters);
}

TEST_F(LegacyProtoParametersTest, OutputPrefixTypeNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);

  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::TINK,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  LegacyProtoParameters parameters(*serialization);
  LegacyProtoParameters other_parameters(*other_serialization);

  EXPECT_TRUE(parameters != other_parameters);
  EXPECT_TRUE(other_parameters != parameters);
  EXPECT_FALSE(parameters == other_parameters);
  EXPECT_FALSE(other_parameters == parameters);
}

TEST_F(LegacyProtoParametersTest, DifferentValueNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);
  TestProto other_proto;
  other_proto.set_num(67890);

  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  util::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           other_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  LegacyProtoParameters parameters(*serialization);
  LegacyProtoParameters other_parameters(*other_serialization);

  EXPECT_TRUE(parameters != other_parameters);
  EXPECT_TRUE(other_parameters != parameters);
  EXPECT_FALSE(parameters == other_parameters);
  EXPECT_FALSE(other_parameters == parameters);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
