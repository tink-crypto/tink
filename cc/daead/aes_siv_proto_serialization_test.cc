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

#include "tink/daead/aes_siv_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_siv.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesSivParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  int key_size;
  absl::optional<int> id;
  std::string output_prefix;
};

class AesSivProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    AesSivProtoSerializationTestSuite, AesSivProtoSerializationTest,
    Values(TestCase{AesSivParameters::Variant::kTink, OutputPrefixType::TINK,
                    /*key_size=*/32, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{AesSivParameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY, /*key_size=*/48,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{AesSivParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                    /*key_size=*/64, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(AesSivProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  AesSivKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(test_case.key_size);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const AesSivParameters* siv_params =
      dynamic_cast<const AesSivParameters*>(params->get());
  ASSERT_THAT(siv_params, NotNull());
  EXPECT_THAT(siv_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(siv_params->KeySizeInBytes(), Eq(test_case.key_size));
}

TEST_F(AesSivProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  AesSivKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey",
          OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesSivProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  AesSivKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey",
          OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesSivProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  AesSivKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  key_format_proto.set_key_size(64);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey",
          OutputPrefixType::RAW, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesSivProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  util::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(test_case.key_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesSivKey"));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesSivKey"));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesSivKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
}

TEST_P(AesSivProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesSivKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey", serialized_key,
          KeyData::SYMMETRIC, test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<AesSivParameters> expected_parameters =
      AesSivParameters::Create(test_case.key_size, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<AesSivKey> expected_key = AesSivKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(AesSivProtoSerializationTest, ParseLegacyKeyAsCrunchy) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(64);
  google::crypto::tink::AesSivKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::LEGACY, /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  const AesSivKey* aes_siv_key = dynamic_cast<const AesSivKey*>(key->get());
  ASSERT_THAT(aes_siv_key, NotNull());
  EXPECT_THAT(aes_siv_key->GetParameters().GetVariant(),
              Eq(AesSivParameters::Variant::kCrunchy));
}

TEST_F(AesSivProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesSivProtoSerializationTest, ParseKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(64);
  google::crypto::tink::AesSivKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesSivProtoSerializationTest, ParseKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(64);
  google::crypto::tink::AesSivKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesSivKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesSivProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  util::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(test_case.key_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesSivKey"));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.AesSivKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesSivKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(std::string(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get()))),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
}

TEST_F(AesSivProtoSerializationTest, SerializeKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterAesSivProtoSerialization(), IsOk());

  util::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(64);
  util::StatusOr<AesSivKey> key = AesSivKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(*key, absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
