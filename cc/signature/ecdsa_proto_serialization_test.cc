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
#include "tink/restricted_big_integer.h"
#include "tink/util/secret_data.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
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
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/subtle/common_enums.h"
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
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
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
  subtle::EllipticCurveType subtle_curve =
      subtle::EllipticCurveType::NIST_P256;
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
                    subtle::EllipticCurveType::NIST_P256,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{EcdsaParameters::Variant::kCrunchy,
                    EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kDer,
                    OutputPrefixType::CRUNCHY, EllipticCurveType::NIST_P384,
                    HashType::SHA384, EcdsaSignatureEncoding::DER,
                    subtle::EllipticCurveType::NIST_P384,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{EcdsaParameters::Variant::kLegacy,
                    EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    OutputPrefixType::LEGACY, EllipticCurveType::NIST_P256,
                    HashType::SHA256, EcdsaSignatureEncoding::IEEE_P1363,
                    subtle::EllipticCurveType::NIST_P256,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{EcdsaParameters::Variant::kNoPrefix,
                    EcdsaParameters::CurveType::kNistP521,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    OutputPrefixType::RAW, EllipticCurveType::NIST_P521,
                    HashType::SHA512, EcdsaSignatureEncoding::IEEE_P1363,
                    subtle::EllipticCurveType::NIST_P521,
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

TEST_P(EcdsaProtoSerializationTest, ParsePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaParams params;
  params.set_curve(test_case.curve);
  params.set_hash_type(test_case.hash);
  params.set_encoding(test_case.encoding);

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(test_case.subtle_curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::EcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
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
              test_case.id.has_value());

  util::StatusOr<EcdsaParameters> expected_parameters =
      EcdsaParameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetCurveType(test_case.curve_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<EcdsaPublicKey> expected_key = EcdsaPublicKey::Create(
      *expected_parameters,
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y)),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(EcdsaProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse EcdsaPublicKey proto")));
}

TEST_F(EcdsaProtoSerializationTest, ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());
  google::crypto::tink::EcdsaPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
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

TEST_P(EcdsaProtoSerializationTest, SerializePublicKeyWorks) {
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

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(test_case.subtle_curve);
  ASSERT_THAT(ec_key, IsOk());

  util::StatusOr<EcdsaPublicKey> key = EcdsaPublicKey::Create(
      *parameters,
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y)),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
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

  google::crypto::tink::EcdsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  // We currently encode with one extra 0 byte at the beginning, to make sure
  // that parsing is correct. See also b/264525021.
  EXPECT_THAT(proto_key.x(), Eq('\0' + ec_key->pub_x));
  EXPECT_THAT(proto_key.y(), Eq('\0' + ec_key->pub_y));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().curve(), Eq(test_case.curve));
  EXPECT_THAT(proto_key.params().hash_type(), Eq(test_case.hash));
  EXPECT_THAT(proto_key.params().encoding(), Eq(test_case.encoding));
}

TEST_P(EcdsaProtoSerializationTest, ParsePrivateKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaParams params;
  params.set_curve(test_case.curve);
  params.set_hash_type(test_case.hash);
  params.set_encoding(test_case.encoding);

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(test_case.subtle_curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::EcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::EcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*private_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  util::StatusOr<EcdsaParameters> expected_parameters =
      EcdsaParameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetCurveType(test_case.curve_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<EcdsaPublicKey> expected_public_key = EcdsaPublicKey::Create(
      *expected_parameters,
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y)),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  util::StatusOr<EcdsaPrivateKey> expected_private_key =
      EcdsaPrivateKey::Create(
          *expected_public_key,
          RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                               InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

TEST_F(EcdsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse EcdsaPrivateKey proto")));
}

TEST_F(EcdsaProtoSerializationTest, ParsePrivateKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::EcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::EcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(EcdsaProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::EcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::EcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  ;
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(EcdsaProtoSerializationTest, SerializePrivateKeyWorks) {
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

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(test_case.subtle_curve);
  ASSERT_THAT(ec_key, IsOk());

  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters,
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y)),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::EcdsaPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  // We currently encode with one extra 0 byte at the beginning, to make sure
  // that parsing is correct.
  EXPECT_THAT(
      proto_key.key_value(),
      Eq('\0' + std::string(util::SecretDataAsStringView(ec_key->priv))));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().hash_type(), Eq(test_case.hash));
  EXPECT_THAT(proto_key.public_key().params().curve(), Eq(test_case.curve));
  EXPECT_THAT(proto_key.public_key().params().encoding(),
              Eq(test_case.encoding));
  EXPECT_THAT(proto_key.public_key().x(), Eq('\0' + ec_key->pub_x));
  EXPECT_THAT(proto_key.public_key().y(), Eq('\0' + ec_key->pub_y));
}

TEST_F(EcdsaProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterEcdsaProtoSerialization(), IsOk());

  util::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters,
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y)),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
