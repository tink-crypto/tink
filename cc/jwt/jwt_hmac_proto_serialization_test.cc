// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_hmac_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtHmacAlgorithm;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtHmacKey";

struct TestCase {
  JwtHmacParameters::KidStrategy strategy;
  OutputPrefixType output_prefix_type;
  JwtHmacParameters::Algorithm algorithm;
  JwtHmacAlgorithm proto_algorithm;
  int key_size;
  absl::optional<std::string> expected_kid;
  absl::optional<int> id;
  std::string output_prefix;
};

class JwtHmacProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(JwtHmacProtoSerializationTest, RegisterTwiceSucceeds) {
  EXPECT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());
  EXPECT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtHmacProtoSerializationTestSuite, JwtHmacProtoSerializationTest,
    Values(TestCase{JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
                    OutputPrefixType::TINK,
                    JwtHmacParameters::Algorithm::kHs256,
                    JwtHmacAlgorithm::HS256,
                    /*key_size=*/16, /*expected_kid=*/"AgMEAA",
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{JwtHmacParameters::KidStrategy::kIgnored,
                    OutputPrefixType::RAW, JwtHmacParameters::Algorithm::kHs384,
                    JwtHmacAlgorithm::HS384,
                    /*key_size=*/32, /*expected_kid=*/absl::nullopt,
                    /*id=*/absl::nullopt, /*output_prefix=*/""},
           TestCase{JwtHmacParameters::KidStrategy::kIgnored,
                    OutputPrefixType::RAW, JwtHmacParameters::Algorithm::kHs512,
                    JwtHmacAlgorithm::HS512,
                    /*key_size=*/32, /*expected_kid=*/absl::nullopt,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(JwtHmacProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(test_case.key_size);
  format.set_algorithm(test_case.proto_algorithm);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT((*parsed)->HasIdRequirement(), test_case.id.has_value());

  util::StatusOr<JwtHmacParameters> expected = JwtHmacParameters::Create(
      test_case.key_size, test_case.strategy, test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(JwtHmacProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse JwtHmacKeyFormat proto")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  JwtHmacKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseParametersWithUnknownAlgorithm) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtHmacAlgorithm")));
}

using JwtHmacParsePrefixTest = TestWithParam<OutputPrefixType>;

INSTANTIATE_TEST_SUITE_P(JwtHmacParsePrefixTestSuite, JwtHmacParsePrefixTest,
                         Values(OutputPrefixType::CRUNCHY,
                                OutputPrefixType::LEGACY,
                                OutputPrefixType::UNKNOWN_PREFIX));

TEST_P(JwtHmacParsePrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, invalid_output_prefix_type, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtHmacKeyFormat")));
}

TEST_P(JwtHmacProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      test_case.key_size, test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  JwtHmacKeyFormat format;
  ASSERT_THAT(
      format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_F(JwtHmacProtoSerializationTest, SerializeParametersWithCustomKidFails) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  EXPECT_THAT(
      serialization.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Unable to serialize JwtHmacParameters::KidStrategy::kCustom")));
}

TEST_P(JwtHmacProtoSerializationTest, ParseKeyWithoutCustomKid) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  util::StatusOr<JwtHmacParameters> expected_parameters =
      JwtHmacParameters::Create(test_case.key_size, test_case.strategy,
                                test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*expected_parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  util::StatusOr<JwtHmacKey> expected_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithCustomKid) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(), IsFalse());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(absl::nullopt));

  util::StatusOr<JwtHmacParameters> expected_parameters =
      JwtHmacParameters::Create(/*key_size_in_bytes=*/32,
                                JwtHmacParameters::KidStrategy::kCustom,
                                JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<JwtHmacKey> expected_key =
      JwtHmacKey::Builder()
          .SetParameters(*expected_parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetCustomKid(key_proto.custom_kid().value())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(JwtHmacProtoSerializationTest, ParseTinkKeyWithCustomKidFails) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  // Omitting expectation on specific error message since the error occurs
  // downstream while building JwtHmacKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse JwtHmacKey proto")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Parsing JwtHmacKey failed: only version 0 is accepted")));
}

TEST_P(JwtHmacParsePrefixTest, ParseKeyWithInvalidPrefix) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyData::SYMMETRIC,
                                              invalid_output_prefix_type,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtHmacKeyFormat")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithUnknownAlgorithm) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtHmacAlgorithm")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithoutSecretKeyAccess) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(JwtHmacProtoSerializationTest, SerializeKeyWithoutCustomKid) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      test_case.key_size, test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  util::StatusOr<JwtHmacKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtHmacKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(proto_key.has_custom_kid(), IsFalse());
}

TEST_F(JwtHmacProtoSerializationTest, SerializeKeyWithCustomKid) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  util::StatusOr<JwtHmacKey> key =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetCustomKid("custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(OutputPrefixType::RAW));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

  google::crypto::tink::JwtHmacKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.algorithm(), Eq(JwtHmacAlgorithm::HS256));
  ASSERT_THAT(proto_key.has_custom_kid(), IsTrue());
  EXPECT_THAT(proto_key.custom_kid().value(), Eq(*key->GetKid()));
}

TEST_F(JwtHmacProtoSerializationTest, SerializeKeyWithoutSecretKeyAccess) {
  ASSERT_THAT(RegisterJwtHmacProtoSerialization(), IsOk());

  util::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kIgnored,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  util::StatusOr<JwtHmacKey> key =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
