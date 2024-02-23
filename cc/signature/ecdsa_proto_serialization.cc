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

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaParams;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::OutputPrefixType;

using EcdsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   EcdsaParameters>;
using EcdsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<EcdsaParameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

util::StatusOr<EcdsaParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return EcdsaParameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return EcdsaParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return EcdsaParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return EcdsaParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    EcdsaParameters::Variant variant) {
  switch (variant) {
    case EcdsaParameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case EcdsaParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case EcdsaParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case EcdsaParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaParameters::Variant");
  }
}

util::StatusOr<EcdsaParameters::HashType> ToHashType(HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA256:
      return EcdsaParameters::HashType::kSha256;
    case HashType::SHA384:
      return EcdsaParameters::HashType::kSha384;
    case HashType::SHA512:
      return EcdsaParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return HashType::SHA256;
    case EcdsaParameters::HashType::kSha384:
      return HashType::SHA384;
    case EcdsaParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaParameters::HashType");
  }
}

util::StatusOr<EcdsaParameters::CurveType> ToCurveType(
    EllipticCurveType curve_type) {
  switch (curve_type) {
    case EllipticCurveType::NIST_P256:
      return EcdsaParameters::CurveType::kNistP256;
    case EllipticCurveType::NIST_P384:
      return EcdsaParameters::CurveType::kNistP384;
    case EllipticCurveType::NIST_P521:
      return EcdsaParameters::CurveType::kNistP521;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EllipticCurveType");
  }
}

util::StatusOr<EllipticCurveType> ToProtoCurveType(
    EcdsaParameters::CurveType curve_type) {
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      return EllipticCurveType::NIST_P256;
    case EcdsaParameters::CurveType::kNistP384:
      return EllipticCurveType::NIST_P384;
    case EcdsaParameters::CurveType::kNistP521:
      return EllipticCurveType::NIST_P521;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaParameters::CurveType");
  }
}

util::StatusOr<EcdsaParameters::SignatureEncoding> ToSignatureEncoding(
    EcdsaSignatureEncoding signature_encoding) {
  switch (signature_encoding) {
    case EcdsaSignatureEncoding::DER:
      return EcdsaParameters::SignatureEncoding::kDer;
    case EcdsaSignatureEncoding::IEEE_P1363:
      return EcdsaParameters::SignatureEncoding::kIeeeP1363;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaSignatureEncoding");
  }
}

util::StatusOr<EcdsaSignatureEncoding> ToProtoSignatureEncoding(
    EcdsaParameters::SignatureEncoding signature_encoding) {
  switch (signature_encoding) {
    case EcdsaParameters::SignatureEncoding::kDer:
      return EcdsaSignatureEncoding::DER;
    case EcdsaParameters::SignatureEncoding::kIeeeP1363:
      return EcdsaSignatureEncoding::IEEE_P1363;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine EcdsaParameters::SignatureEncoding");
  }
}

util::StatusOr<EcdsaParameters> ToParameters(
    OutputPrefixType output_prefix_type, const EcdsaParams& params) {
  util::StatusOr<EcdsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<EcdsaParameters::HashType> hash_type =
      ToHashType(params.hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<EcdsaParameters::CurveType> curve_type =
      ToCurveType(params.curve());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  util::StatusOr<EcdsaParameters::SignatureEncoding> encoding =
      ToSignatureEncoding(params.encoding());
  if (!encoding.ok()) {
    return encoding.status();
  }

  return EcdsaParameters::Builder()
      .SetVariant(*variant)
      .SetHashType(*hash_type)
      .SetCurveType(*curve_type)
      .SetSignatureEncoding(*encoding)
      .Build();
}

util::StatusOr<EcdsaParams> FromParameters(const EcdsaParameters& parameters) {
  util::StatusOr<EllipticCurveType> curve =
      ToProtoCurveType(parameters.GetCurveType());
  if (!curve.ok()) {
    return curve.status();
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<EcdsaSignatureEncoding> encoding =
      ToProtoSignatureEncoding(parameters.GetSignatureEncoding());
  if (!encoding.ok()) {
    return encoding.status();
  }

  EcdsaParams params;
  params.set_curve(*curve);
  params.set_hash_type(*hash_type);
  params.set_encoding(*encoding);

  return params;
}

util::StatusOr<EcdsaParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EcdsaParameters.");
  }

  EcdsaKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "EcdsaKeyFormat proto is missing params field.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.params());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const EcdsaParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<EcdsaParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  EcdsaKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

EcdsaProtoParametersParserImpl& EcdsaProtoParametersParser() {
  static absl::NoDestructor<EcdsaProtoParametersParserImpl> parser(
      kPrivateTypeUrl, ParseParameters);
  return *parser;
}

EcdsaProtoParametersSerializerImpl& EcdsaProtoParametersSerializer() {
  static absl::NoDestructor<EcdsaProtoParametersSerializerImpl> serializer(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

}  // namespace

util::Status RegisterEcdsaProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&EcdsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(&EcdsaProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
