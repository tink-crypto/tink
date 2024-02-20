// Copyright 2024 Google LLC
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

#include "tink/aead/chacha20_poly1305_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/chacha20_poly1305.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::ChaCha20Poly1305KeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

struct TestCase {
  ChaCha20Poly1305Parameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

class ChaCha20Poly1305ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  ChaCha20Poly1305ProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(ChaCha20Poly1305ProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    ChaCha20Poly1305ProtoSerializationTestSuite,
    ChaCha20Poly1305ProtoSerializationTest,
    Values(TestCase{ChaCha20Poly1305Parameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{ChaCha20Poly1305Parameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{ChaCha20Poly1305Parameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(ChaCha20Poly1305ProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          ChaCha20Poly1305KeyFormat().SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const ChaCha20Poly1305Parameters* chacha20_poly1305_params =
      dynamic_cast<const ChaCha20Poly1305Parameters*>(params->get());
  ASSERT_THAT(chacha20_poly1305_params, NotNull());
  EXPECT_THAT(chacha20_poly1305_params->GetVariant(), Eq(test_case.variant));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest,
       ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          ChaCha20Poly1305KeyFormat().SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(ChaCha20Poly1305ProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
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

  ChaCha20Poly1305KeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
}

TEST_P(ChaCha20Poly1305ProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::ChaCha20Poly1305Key key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<ChaCha20Poly1305Parameters> expected_parameters =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<ChaCha20Poly1305Key> expected_key =
      ChaCha20Poly1305Key::Create(
          expected_parameters->GetVariant(),
          RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
          test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest, ParseLegacyKeyAsCrunchy) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::ChaCha20Poly1305Key key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyData::SYMMETRIC,
                                              OutputPrefixType::LEGACY,
                                              /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  const ChaCha20Poly1305Key* chacha20_poly1305_key =
      dynamic_cast<const ChaCha20Poly1305Key*>(key->get());
  ASSERT_THAT(chacha20_poly1305_key, NotNull());
  EXPECT_THAT(chacha20_poly1305_key->GetParameters().GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kCrunchy));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest,
       ParseKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest, ParseKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(64);
  google::crypto::tink::ChaCha20Poly1305Key key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest, ParseKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(64);
  google::crypto::tink::ChaCha20Poly1305Key key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(ChaCha20Poly1305ProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  util::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      parameters->GetVariant(),
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
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

  google::crypto::tink::ChaCha20Poly1305Key proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(32));
}

TEST_F(ChaCha20Poly1305ProtoSerializationTest, SerializeKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterChaCha20Poly1305ProtoSerialization(), IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  util::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      parameters->GetVariant(),
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
