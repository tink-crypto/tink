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
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_encoding_util.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
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
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

using EcdsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   EcdsaParameters>;
using EcdsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<EcdsaParameters,
                                       internal::ProtoParametersSerialization>;
using EcdsaProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, EcdsaPublicKey>;
using EcdsaProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<EcdsaPublicKey,
                                internal::ProtoKeySerialization>;
using EcdsaProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, EcdsaPrivateKey>;
using EcdsaProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<EcdsaPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
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

util::StatusOr<int> getEncodingLength(EcdsaParameters::CurveType curveType) {
  // We currently encode with one extra 0 byte at the beginning, to make sure
  // that parsing is correct. See also b/264525021.
  switch (curveType) {
    case EcdsaParameters::CurveType::kNistP256:
      return 33;
    case EcdsaParameters::CurveType::kNistP384:
      return 49;
    case EcdsaParameters::CurveType::kNistP521:
      return 67;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Unable to serialize CurveType");
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

util::StatusOr<EcdsaPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EcdsaPublicKey.");
  }

  google::crypto::tink::EcdsaPublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<EcdsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  EcPoint public_point(BigInteger(proto_key.x()), BigInteger(proto_key.y()));
  return EcdsaPublicKey::Create(*parameters, public_point,
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

util::StatusOr<EcdsaPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EcdsaPrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  google::crypto::tink::EcdsaPrivateKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaPrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<EcdsaParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<EcdsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  EcPoint public_point(BigInteger(proto_key.public_key().x()),
                       BigInteger(proto_key.public_key().y()));
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, public_point, serialization.IdRequirement(),
      GetPartialKeyAccess());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(proto_key.key_value(), *token);
  return EcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess());
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

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const EcdsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<EcdsaParams> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<int> enc_length =
      getEncodingLength(key.GetParameters().GetCurveType());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  util::StatusOr<std::string> x = internal::GetValueOfFixedLength(
      key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
      enc_length.value());
  if (!x.ok()) {
    return x.status();
  }

  util::StatusOr<std::string> y = internal::GetValueOfFixedLength(
      key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue(),
      enc_length.value());
  if (!y.ok()) {
    return y.status();
  }

  google::crypto::tink::EcdsaPublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  proto_key.set_x(*x);
  proto_key.set_y(*y);

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const EcdsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedBigInteger> restricted_input =
      key.GetPrivateKeyValue(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<EcdsaParams> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<int> enc_length =
      getEncodingLength(key.GetPublicKey().GetParameters().GetCurveType());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  google::crypto::tink::EcdsaPublicKey proto_public_key;
  proto_public_key.set_version(0);
  *proto_public_key.mutable_params() = *params;
  proto_public_key.set_x(*internal::GetValueOfFixedLength(
      key.GetPublicKey()
          .GetPublicPoint(GetPartialKeyAccess())
          .GetX()
          .GetValue(),
      enc_length.value()));
  proto_public_key.set_y(*internal::GetValueOfFixedLength(
      key.GetPublicKey()
          .GetPublicPoint(GetPartialKeyAccess())
          .GetY()
          .GetValue(),
      enc_length.value()));

  google::crypto::tink::EcdsaPrivateKey proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = proto_public_key;
  proto_private_key.set_key_value(*internal::GetValueOfFixedLength(
      restricted_input->GetSecret(*token), *enc_length));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(proto_private_key.SerializeAsString(), *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, restricted_output, KeyData::ASYMMETRIC_PRIVATE,
      *output_prefix_type, key.GetIdRequirement());
}

EcdsaProtoParametersParserImpl& EcdsaProtoParametersParser() {
  static auto* parser =
      new EcdsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

EcdsaProtoParametersSerializerImpl& EcdsaProtoParametersSerializer() {
  static auto* serializer = new EcdsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

EcdsaProtoPublicKeyParserImpl& EcdsaProtoPublicKeyParser() {
  static auto* parser =
      new EcdsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

EcdsaProtoPublicKeySerializerImpl& EcdsaProtoPublicKeySerializer() {
  static auto* serializer =
      new EcdsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

EcdsaProtoPrivateKeyParserImpl& EcdsaProtoPrivateKeyParser() {
  static auto* parser =
      new EcdsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

EcdsaProtoPrivateKeySerializerImpl& EcdsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new EcdsaProtoPrivateKeySerializerImpl(SerializePrivateKey);
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

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(&EcdsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&EcdsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&EcdsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&EcdsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&EcdsaProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
