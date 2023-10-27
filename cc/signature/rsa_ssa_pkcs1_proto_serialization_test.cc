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
#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPkcs1KeyFormat;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  RsaSsaPkcs1Parameters::Variant variant;
  OutputPrefixType output_prefix_type;
  RsaSsaPkcs1Parameters::HashType hash_type;
  HashType proto_hash_type;
  int modulus_size_in_bits;
  absl::optional<int> id;
  std::string output_prefix;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";

class RsaSsaPkcs1ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(RsaSsaPkcs1ProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1ProtoSerializationTestSuite, RsaSsaPkcs1ProtoSerializationTest,
    Values(TestCase{RsaSsaPkcs1Parameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    RsaSsaPkcs1Parameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    RsaSsaPkcs1Parameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    RsaSsaPkcs1Parameters::HashType::kSha384, HashType::SHA384,
                    /*modulus_size=*/3072, /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW,
                    RsaSsaPkcs1Parameters::HashType::kSha512, HashType::SHA512,
                    /*modulus_size=*/3072, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPkcs1ProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(test_case.proto_hash_type);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());
  const RsaSsaPkcs1Parameters* rsa_ssa_pkcs1_parameters =
      dynamic_cast<const RsaSsaPkcs1Parameters*>(parameters->get());
  ASSERT_THAT(rsa_ssa_pkcs1_parameters, NotNull());
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetPublicExponent(),
              Eq(BigInteger(kF4Str)));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest, ParseParametersLegacyAsCrunchy) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::SHA256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::LEGACY,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT((*parameters)->HasIdRequirement(), IsTrue());

  const RsaSsaPkcs1Parameters* rsa_ssa_pkcs1_parameters =
      dynamic_cast<const RsaSsaPkcs1Parameters*>(parameters->get());

  ASSERT_THAT(rsa_ssa_pkcs1_parameters, NotNull());
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetVariant(),
              Eq(RsaSsaPkcs1Parameters::Variant::kCrunchy));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetHashType(),
              Eq(RsaSsaPkcs1Parameters::HashType::kSha256));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetPublicExponent(),
              Eq(BigInteger(kF4Str)));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::SHA256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest, ParseParametersWithUnkownHashFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::UNKNOWN_HASH);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPkcs1ProtoSerializationTest, SerializeParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());

  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().hash_type(), Eq(test_case.proto_hash_type));
  EXPECT_THAT(key_format.modulus_size_in_bits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
