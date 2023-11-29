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

#include "tink/mac/hmac_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  HmacParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  HmacParameters::HashType hash_type;
  HashType proto_hash_type;
  int key_size;
  int tag_size;
  int total_size;
  absl::optional<int> id;
  std::string output_prefix;
};

class HmacProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(HmacProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    HmacProtoSerializationTestSuite, HmacProtoSerializationTest,
    Values(TestCase{HmacParameters::Variant::kTink, OutputPrefixType::TINK,
                    HmacParameters::HashType::kSha1, HashType::SHA1,
                    /*key_size=*/16, /*cryptographic_tag_size=*/10,
                    /*total_size=*/15, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{HmacParameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    HmacParameters::HashType::kSha224, HashType::SHA224,
                    /*key_size=*/16, /*tag_size=*/12, /*total_size=*/17,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{HmacParameters::Variant::kLegacy, OutputPrefixType::LEGACY,
                    HmacParameters::HashType::kSha256, HashType::SHA256,
                    /*key_size=*/32, /*cryptographic_tag_size=*/14,
                    /*total_tag_size=*/19, /*id=*/0x01020304,
                    /*output_prefix=*/std::string("\x00\x01\x02\x03\x04", 5)},
           TestCase{HmacParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                    HmacParameters::HashType::kSha384, HashType::SHA384,
                    /*key_size=*/32, /*cryptographic_tag_size=*/16,
                    /*total_tag_size=*/16, /*id=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{HmacParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                    HmacParameters::HashType::kSha512, HashType::SHA512,
                    /*key_size=*/32, /*cryptographic_tag_size=*/20,
                    /*total_tag_size=*/20, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(HmacProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  HmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(test_case.key_size);
  key_format_proto.mutable_params()->set_tag_size(test_case.tag_size);
  key_format_proto.mutable_params()->set_hash(test_case.proto_hash_type);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<HmacParameters> expected_parameters =
      HmacParameters::Create(test_case.key_size, test_case.tag_size,
                             test_case.hash_type, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());
  ASSERT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(HmacProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey",
          OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HmacProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  HmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.set_version(1);  // Invalid version.
  key_format_proto.mutable_params()->set_tag_size(10);
  key_format_proto.mutable_params()->set_hash(HashType::SHA256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey",
          OutputPrefixType::RAW, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HmacProtoSerializationTest, ParseParametersWithUnknownHashType) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  HmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.set_version(0);
  key_format_proto.mutable_params()->set_tag_size(10);
  key_format_proto.mutable_params()->set_hash(HashType::UNKNOWN_HASH);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey",
          OutputPrefixType::RAW, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HmacProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  HmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.mutable_params()->set_tag_size(10);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey",
          OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HmacProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  util::StatusOr<HmacParameters> parameters =
      HmacParameters::Create(test_case.key_size, test_case.tag_size,
                             test_case.hash_type, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.HmacKey"));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.HmacKey"));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  HmacKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_THAT(key_format.key_size(), Eq(test_case.key_size));
  ASSERT_THAT(key_format.params().tag_size(), Eq(test_case.tag_size));
  ASSERT_THAT(key_format.params().hash(), Eq(test_case.proto_hash_type));
}

TEST_P(HmacProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::HmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(test_case.tag_size);
  key_proto.mutable_params()->set_hash(test_case.proto_hash_type);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey", serialized_key,
          KeyData::SYMMETRIC, test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  util::StatusOr<HmacParameters> expected_parameters =
      HmacParameters::Create(test_case.key_size, test_case.tag_size,
                             test_case.hash_type, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());
  util::StatusOr<HmacKey> expected_key = HmacKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());

  ASSERT_THAT(expected_key, IsOk());
  ASSERT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(HmacProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(10);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HmacProtoSerializationTest, ParseKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HmacKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(10);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HmacProtoSerializationTest, ParseKeyWithoutSecretKeyAccess) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(10);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.HmacKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, absl::nullopt);
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HmacProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  util::StatusOr<HmacParameters> parameters =
      HmacParameters::Create(test_case.key_size, test_case.tag_size,
                             test_case.hash_type, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  util::StatusOr<HmacKey> key = HmacKey::Create(
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
              Eq("type.googleapis.com/google.crypto.tink.HmacKey"));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.HmacKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HmacKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(std::string(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get()))),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
  EXPECT_THAT(proto_key.params().tag_size(), Eq(test_case.tag_size));
  EXPECT_THAT(proto_key.params().hash(), Eq(test_case.proto_hash_type));
}

TEST_F(HmacProtoSerializationTest, SerializeKeyWithoutSecretKeyAccess) {
  ASSERT_THAT(RegisterHmacProtoSerialization(), IsOk());

  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      /*key_size_in_bytes=*/16, /*cryptographic_tag_size_in_bytes=*/10,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  util::StatusOr<HmacKey> key = HmacKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(*key, absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
