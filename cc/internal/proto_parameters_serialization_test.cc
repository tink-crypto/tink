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

#include "tink/internal/proto_parameters_serialization.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestProto;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

class ProtoParametersSerializationTest : public ::testing::Test {
 protected:
  bool Equals(ProtoParametersSerialization serialization,
              ProtoParametersSerialization other) {
    return serialization.EqualsWithPotentialFalseNegatives(other);
  }
};

TEST_F(ProtoParametersSerializationTest, CreateFromIndividualComponents) {
  TestProto test_proto;
  test_proto.set_num(12345);
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  EXPECT_THAT(serialization->ObjectIdentifier(), "type_url");
  EXPECT_THAT(serialization->GetKeyTemplate().type_url(), "type_url");
  EXPECT_THAT(serialization->GetKeyTemplate().output_prefix_type(),
              OutputPrefixType::RAW);
  EXPECT_THAT(serialization->GetKeyTemplate().value(),
              test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(serialization->GetKeyTemplate().value());
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest, CreateFromKeyTemplate) {
  TestProto test_proto;
  test_proto.set_num(12345);
  KeyTemplate key_template;
  key_template.set_value(test_proto.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url("type_url");
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template);
  ASSERT_THAT(serialization.status(), IsOk());

  EXPECT_THAT(serialization->ObjectIdentifier(), "type_url");
  EXPECT_THAT(serialization->GetKeyTemplate().type_url(), "type_url");
  EXPECT_THAT(serialization->GetKeyTemplate().output_prefix_type(),
              OutputPrefixType::TINK);
  EXPECT_THAT(serialization->GetKeyTemplate().value(),
              test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(serialization->GetKeyTemplate().value());
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest, Equals) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsTrue());
}

TEST_F(ProtoParametersSerializationTest, TypeUrlNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);

  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());


  util::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("other_url", OutputPrefixType::RAW,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoParametersSerializationTest, OutputPrefixTypeNotEqual) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoParametersSerializationTest, DifferentValueNotEqual) {
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

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
