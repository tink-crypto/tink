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

#include "tink/signature/ecdsa_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaParams;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

struct TestCase {
  EcdsaParameters::Variant variant = EcdsaParameters::Variant::kTink;
  EcdsaParameters::CurveType curve_type = EcdsaParameters::CurveType::kNistP256;
  EcdsaParameters::HashType hash_type = EcdsaParameters::HashType::kSha256;
  EcdsaParameters::SignatureEncoding signature_encoding =
      EcdsaParameters::SignatureEncoding::kDer;
  OutputPrefixType output_prefix_type = OutputPrefixType::TINK;
  EllipticCurveType curve = EllipticCurveType::NIST_P256;
  HashType hash = HashType::SHA256;
  EcdsaSignatureEncoding encoding = EcdsaSignatureEncoding::DER;
  absl::optional<int> id;
  std::string output_prefix;
};

class EcdsaProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  EcdsaProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(EcdsaProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    EcdsaProtoSerializationTestSuite, EcdsaProtoSerializationTest,
    Values(TestCase{EcdsaParameters::Variant::kTink,
                    EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    OutputPrefixType::TINK, EllipticCurveType::NIST_P256,
                    HashType::SHA256, EcdsaSignatureEncoding::DER,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{EcdsaParameters::Variant::kCrunchy,
                    EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kDer,
                    OutputPrefixType::CRUNCHY, EllipticCurveType::NIST_P384,
                    HashType::SHA384, EcdsaSignatureEncoding::DER,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{EcdsaParameters::Variant::kLegacy,
                    EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    OutputPrefixType::LEGACY, EllipticCurveType::NIST_P256,
                    HashType::SHA256, EcdsaSignatureEncoding::IEEE_P1363,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{EcdsaParameters::Variant::kNoPrefix,
                    EcdsaParameters::CurveType::kNistP521,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    OutputPrefixType::RAW, EllipticCurveType::NIST_P521,
                    HashType::SHA512, EcdsaSignatureEncoding::IEEE_P1363,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(EcdsaProtoSerializationTest, ParseParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  EcdsaParams& params = *key_format_proto.mutable_params();
  params.set_curve(test_case.curve);
  params.set_hash_type(test_case.hash);
  params.set_encoding(test_case.encoding);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_EQ((*parameters)->HasIdRequirement(), test_case.id.has_value());

  const EcdsaParameters* ecdsa_parameters =
      dynamic_cast<const EcdsaParameters*>(parameters->get());
  ASSERT_THAT(ecdsa_parameters, NotNull());
  EXPECT_THAT(ecdsa_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(ecdsa_parameters->GetCurveType(), Eq(test_case.curve_type));
  EXPECT_THAT(ecdsa_parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(ecdsa_parameters->GetSignatureEncoding(),
              Eq(test_case.signature_encoding));
}

TEST_F(EcdsaProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse EcdsaKeyFormat proto")));
}

TEST_F(EcdsaProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  EcdsaParams& params = *key_format_proto.mutable_params();
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(EcdsaProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  EcdsaParams& params = *key_format_proto.mutable_params();
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine output prefix type")));
}

TEST_F(EcdsaProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("EcdsaKeyFormat proto is missing params")));
}

TEST_F(EcdsaProtoSerializationTest, ParseParametersWithUnkownCurveTypeFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  EcdsaParams& params = *key_format_proto.mutable_params();
  params.set_curve(EllipticCurveType::UNKNOWN_CURVE);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine EllipticCurveType")));
}

TEST_F(EcdsaProtoSerializationTest, ParseParametersWithUnkownHashTypeFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  EcdsaParams& params = *key_format_proto.mutable_params();
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::UNKNOWN_HASH);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine HashType")));
}

TEST_F(EcdsaProtoSerializationTest, ParseParametersWithUnkownEncodingFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaKeyFormat key_format_proto;
  EcdsaParams& params = *key_format_proto.mutable_params();
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::UNKNOWN_ENCODING);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine EcdsaSignatureEncoding")));
}

TEST_P(EcdsaProtoSerializationTest, SerializeParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetCurveType(test_case.curve_type)
          .SetSignatureEncoding(test_case.signature_encoding)
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

  EcdsaKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().hash_type(), Eq(test_case.hash));
  EXPECT_THAT(key_format.params().curve(), Eq(test_case.curve));
  EXPECT_THAT(key_format.params().encoding(), Eq(test_case.encoding));
}
}  // namespace
}  // namespace tink
}  // namespace crypto
