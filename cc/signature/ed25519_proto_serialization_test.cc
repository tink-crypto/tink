// Copyright 2023 Google LLC
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

#include "tink/signature/ed25519_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Ed25519KeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  Ed25519Parameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

class Ed25519ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    Ed25519ProtoSerializationTestSuite, Ed25519ProtoSerializationTest,
    Values(TestCase{Ed25519Parameters::Variant::kTink, OutputPrefixType::TINK,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Ed25519Parameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{Ed25519Parameters::Variant::kLegacy,
                    OutputPrefixType::LEGACY, /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{Ed25519Parameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(Ed25519ProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  Ed25519KeyFormat key_format_proto;
  key_format_proto.set_version(0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const Ed25519Parameters* ed25519_params =
      dynamic_cast<const Ed25519Parameters*>(params->get());
  ASSERT_THAT(ed25519_params, NotNull());
  EXPECT_THAT(ed25519_params->GetVariant(), Eq(test_case.variant));
}

TEST_F(Ed25519ProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
          OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  Ed25519KeyFormat key_format_proto;
  key_format_proto.set_version(0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
          OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  Ed25519KeyFormat key_format_proto;
  key_format_proto.set_version(1);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
          OutputPrefixType::RAW, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519ProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  Ed25519KeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
}

TEST_P(Ed25519ProtoSerializationTest, ParsePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::Ed25519PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<Ed25519Parameters> expected_parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<Ed25519PublicKey> expected_key = Ed25519PublicKey::Create(
      *expected_parameters, raw_key_bytes, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          serialized_key, KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Ed25519ProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::Ed25519PublicKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          serialized_key, KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519ProtoSerializationTest, SerializePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEd25519ProtoSerialization(), IsOk());

  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  util::StatusOr<Ed25519PublicKey> key = Ed25519PublicKey::Create(
      *parameters, raw_key_bytes, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PublicKey"));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PublicKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::Ed25519PublicKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(std::string(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get()))),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), SizeIs(32));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
