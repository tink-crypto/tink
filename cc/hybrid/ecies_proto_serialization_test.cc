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

#include "tink/hybrid/ecies_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::EciesAeadDemParams;
using ::google::crypto::tink::EciesAeadHkdfKeyFormat;
using ::google::crypto::tink::EciesAeadHkdfParams;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EciesHkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
constexpr absl::string_view kSalt = "2024ab";

struct TestCase {
  EciesParameters::Variant variant;
  EciesParameters::CurveType curve_type;
  EciesParameters::HashType hash_type;
  EciesParameters::DemId dem_id;
  absl::optional<EciesParameters::PointFormat> point_format;
  absl::optional<std::string> salt;
  OutputPrefixType output_prefix_type;
  EciesHkdfKemParams kem_params;
  EciesAeadDemParams dem_params;
  EcPointFormat ec_point_format;
  absl::optional<int> id;
  std::string output_prefix;
};

class EciesProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  EciesProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(EciesProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());
}

EciesHkdfKemParams CreateKemParams(EllipticCurveType curve_type,
                                   HashType hash_type, absl::string_view salt) {
  EciesHkdfKemParams kem_params;
  kem_params.set_curve_type(curve_type);
  kem_params.set_hkdf_hash_type(hash_type);
  kem_params.set_hkdf_salt(salt);
  return kem_params;
}

EciesAeadDemParams CreateAesGcmDemParams(int key_size_in_bytes) {
  AesGcmKeyFormat format;
  format.set_key_size(key_size_in_bytes);
  format.set_version(0);

  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());

  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

EciesAeadDemParams CreateAes256SivDemParams() {
  AesSivKeyFormat format;
  format.set_key_size(64);
  format.set_version(0);

  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesSivKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());

  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

INSTANTIATE_TEST_SUITE_P(
    EciesProtoSerializationTestSuite, EciesProtoSerializationTest,
    Values(TestCase{EciesParameters::Variant::kTink,
                    EciesParameters::CurveType::kNistP256,
                    EciesParameters::HashType::kSha256,
                    EciesParameters::DemId::kAes128GcmRaw,
                    EciesParameters::PointFormat::kCompressed, kSalt.data(),
                    OutputPrefixType::TINK,
                    CreateKemParams(EllipticCurveType::NIST_P256,
                                    HashType::SHA256, kSalt),
                    CreateAesGcmDemParams(16), EcPointFormat::COMPRESSED,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{EciesParameters::Variant::kCrunchy,
                    EciesParameters::CurveType::kNistP384,
                    EciesParameters::HashType::kSha384,
                    EciesParameters::DemId::kAes256GcmRaw,
                    EciesParameters::PointFormat::kLegacyUncompressed,
                    /*salt=*/absl::nullopt, OutputPrefixType::CRUNCHY,
                    CreateKemParams(EllipticCurveType::NIST_P384,
                                    HashType::SHA384, /*salt=*/""),
                    CreateAesGcmDemParams(32),
                    EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{EciesParameters::Variant::kTink,
                    EciesParameters::CurveType::kNistP521,
                    EciesParameters::HashType::kSha512,
                    EciesParameters::DemId::kAes256SivRaw,
                    EciesParameters::PointFormat::kUncompressed,
                    /*salt=*/absl::nullopt, OutputPrefixType::TINK,
                    CreateKemParams(EllipticCurveType::NIST_P521,
                                    HashType::SHA512, /*salt=*/""),
                    CreateAes256SivDemParams(), EcPointFormat::UNCOMPRESSED,
                    /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{EciesParameters::Variant::kNoPrefix,
                    EciesParameters::CurveType::kX25519,
                    EciesParameters::HashType::kSha256,
                    EciesParameters::DemId::kAes128GcmRaw,
                    /*point_format=*/absl::nullopt,
                    /*salt=*/kSalt.data(), OutputPrefixType::RAW,
                    CreateKemParams(EllipticCurveType::CURVE25519,
                                    HashType::SHA256, /*salt=*/kSalt),
                    CreateAesGcmDemParams(16), EcPointFormat::COMPRESSED,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(EciesProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = test_case.kem_params;
  *params.mutable_dem_params() = test_case.dem_params;
  params.set_ec_point_format(test_case.ec_point_format);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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

  const EciesParameters* ecies_parameters =
      dynamic_cast<const EciesParameters*>(parameters->get());
  ASSERT_THAT(ecies_parameters, NotNull());
  EXPECT_THAT(ecies_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(ecies_parameters->GetCurveType(), Eq(test_case.curve_type));
  EXPECT_THAT(ecies_parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(ecies_parameters->GetDemId(), Eq(test_case.dem_id));
  EXPECT_THAT(ecies_parameters->GetNistCurvePointFormat(),
              Eq(test_case.point_format));
  EXPECT_THAT(ecies_parameters->GetSalt(), Eq(test_case.salt));
}

TEST_F(EciesProtoSerializationTest, ParseLegacyAsCrunchySucceeds) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::LEGACY,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  const EciesParameters* ecies_parameters =
      dynamic_cast<const EciesParameters*>(parameters->get());
  ASSERT_THAT(ecies_parameters, NotNull());
  EXPECT_THAT(ecies_parameters->GetVariant(),
              Eq(EciesParameters::Variant::kCrunchy));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse EciesAeadHkdfKeyFormat proto")));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine EciesParameters::Variant")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingKemFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Missing EciesAeadHkdfParams.kem_params field")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingDemFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Missing EciesAeadHkdfParams.dem_params field")));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithMissingPointFormatFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Could not determine EciesParameters::PointFormat")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingSaltSucceeds) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  params.mutable_kem_params()->clear_hkdf_salt();  // Missing salt.
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  const EciesParameters* ecies_parameters =
      dynamic_cast<const EciesParameters*>(parameters->get());
  ASSERT_THAT(ecies_parameters, NotNull());
  EXPECT_THAT(ecies_parameters->GetSalt(), Eq(absl::nullopt));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingParamsFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfKeyFormat key_format_proto;

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
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("EciesAeadHkdfKeyFormat proto is missing params field")));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithMissingKeyTemplateFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.mutable_dem_params()->clear_aead_dem();  // Missing key template.
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
                       HasSubstr("Missing EciesAeadDemParams.aead_dem field")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithUnkownCurveTypeFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = CreateKemParams(
      EllipticCurveType::UNKNOWN_CURVE, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Could not determine EciesParameters::CurveType")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithUnkownHashTypeFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = CreateKemParams(EllipticCurveType::NIST_P256,
                                                 HashType::UNKNOWN_HASH, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Could not determine EciesParameters::HashType")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithUnkownPointFormatFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::UNKNOWN_FORMAT);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Could not determine EciesParameters::PointFormat")));
}

TEST_P(EciesProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  util::StatusOr<EciesParameters> parameters = parameters_builder.Build();
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

  EciesAeadHkdfKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());

  ASSERT_THAT(key_format.params().has_kem_params(), IsTrue());
  EXPECT_THAT(key_format.params().kem_params().curve_type(),
              Eq(test_case.kem_params.curve_type()));
  EXPECT_THAT(key_format.params().kem_params().hkdf_hash_type(),
              Eq(test_case.kem_params.hkdf_hash_type()));
  EXPECT_THAT(key_format.params().kem_params().hkdf_salt(),
              Eq(test_case.kem_params.hkdf_salt()));

  ASSERT_THAT(key_format.params().has_dem_params(), IsTrue());
  ASSERT_THAT(key_format.params().dem_params().has_aead_dem(), IsTrue());
  EXPECT_THAT(key_format.params().dem_params().aead_dem().type_url(),
              Eq(test_case.dem_params.aead_dem().type_url()));
  EXPECT_THAT(key_format.params().dem_params().aead_dem().output_prefix_type(),
              Eq(test_case.dem_params.aead_dem().output_prefix_type()));
  EXPECT_THAT(key_format.params().dem_params().aead_dem().value(),
              Eq(test_case.dem_params.aead_dem().value()));
  EXPECT_THAT(key_format.params().ec_point_format(),
              Eq(test_case.ec_point_format));
}

struct KeyPair {
  // Public key coordinates
  std::string x;
  std::string y;  // Empty for X25519 public keys.
  std::string private_key;
};

util::StatusOr<KeyPair> GenerateKeyPair(subtle::EllipticCurveType curve) {
  if (curve == subtle::EllipticCurveType::CURVE25519) {
    util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
        internal::NewX25519Key();
    if (!x25519_key.ok()) {
      return x25519_key.status();
    }
    const std::string public_key_bytes =
        std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                    internal::X25519KeyPubKeySize());
    const std::string private_key_bytes =
        std::string(reinterpret_cast<const char*>((*x25519_key)->private_key),
                    internal::X25519KeyPrivKeySize());
    return KeyPair{/*x=*/public_key_bytes, /*y=*/"", private_key_bytes};
  }
  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(curve);
  if (!ec_key.ok()) {
    return ec_key.status();
  }
  return KeyPair{
      ec_key->pub_x,
      ec_key->pub_y,
      std::string(util::SecretDataAsStringView(ec_key->priv)),
  };
}

TEST_P(EciesProtoSerializationTest, ParsePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = test_case.kem_params;
  *params.mutable_dem_params() = test_case.dem_params;
  params.set_ec_point_format(test_case.ec_point_format);

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(test_case.kem_params.curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_x(key_pair->x);
  key_proto.set_y(key_pair->y);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              Eq(test_case.id.has_value()));

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  util::StatusOr<EciesParameters> expected_parameters =
      parameters_builder.Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<EciesPublicKey> expected_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    expected_key = EciesPublicKey::CreateForNistCurve(
        *expected_parameters,
        EcPoint(BigInteger(key_pair->x), BigInteger(key_pair->y)), test_case.id,
        GetPartialKeyAccess());
  } else {
    expected_key = EciesPublicKey::CreateForCurveX25519(
        *expected_parameters, key_pair->x, test_case.id, GetPartialKeyAccess());
  }
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(EciesProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse EciesAeadHkdfPublicKey proto")));
}

TEST_F(EciesProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);

  util::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_x(key_pair->x);
  key_proto.set_y(key_pair->y);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(EciesProtoSerializationTest, SerializePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  util::StatusOr<EciesParameters> parameters = parameters_builder.Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(test_case.kem_params.curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<EciesPublicKey> public_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    public_key = EciesPublicKey::CreateForNistCurve(
        *parameters, EcPoint(BigInteger(key_pair->x), BigInteger(key_pair->y)),
        test_case.id, GetPartialKeyAccess());
  } else {
    public_key = EciesPublicKey::CreateForCurveX25519(
        *parameters, key_pair->x, test_case.id, GetPartialKeyAccess());
  }
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *public_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  EciesAeadHkdfPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  const std::string prefix =
      (test_case.curve_type == EciesParameters::CurveType::kX25519)
          ? ""
          : std::string("\x00", 1);
  EXPECT_THAT(proto_key.x(), Eq(absl::StrCat(prefix, key_pair->x)));
  EXPECT_THAT(proto_key.y(), Eq(absl::StrCat(prefix, key_pair->y)));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ec_point_format(),
              Eq(test_case.ec_point_format));

  ASSERT_THAT(proto_key.params().has_kem_params(), IsTrue());
  EXPECT_THAT(proto_key.params().kem_params().curve_type(),
              Eq(test_case.kem_params.curve_type()));
  EXPECT_THAT(proto_key.params().kem_params().hkdf_hash_type(),
              Eq(test_case.kem_params.hkdf_hash_type()));
  EXPECT_THAT(proto_key.params().kem_params().hkdf_salt(),
              Eq(test_case.kem_params.hkdf_salt()));

  ASSERT_THAT(proto_key.params().has_dem_params(), IsTrue());
  ASSERT_THAT(proto_key.params().dem_params().has_aead_dem(), IsTrue());
  EXPECT_THAT(proto_key.params().dem_params().aead_dem().type_url(),
              Eq(test_case.dem_params.aead_dem().type_url()));
  EXPECT_THAT(proto_key.params().dem_params().aead_dem().output_prefix_type(),
              Eq(test_case.dem_params.aead_dem().output_prefix_type()));
  EXPECT_THAT(proto_key.params().dem_params().aead_dem().value(),
              Eq(test_case.dem_params.aead_dem().value()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
