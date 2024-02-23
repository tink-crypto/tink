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

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
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
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::EciesAeadDemParams;
using ::google::crypto::tink::EciesAeadHkdfKeyFormat;
using ::google::crypto::tink::EciesAeadHkdfParams;
using ::google::crypto::tink::EciesAeadHkdfPrivateKey;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EciesHkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

using EciesProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   EciesParameters>;
using EciesProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<EciesParameters,
                                       internal::ProtoParametersSerialization>;
using EciesProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, EciesPublicKey>;
using EciesProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<EciesPublicKey,
                                internal::ProtoKeySerialization>;
using EciesProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, EciesPrivateKey>;
using EciesProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<EciesPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

util::StatusOr<EciesParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return EciesParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return EciesParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return EciesParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EciesParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    EciesParameters::Variant variant) {
  switch (variant) {
    case EciesParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case EciesParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case EciesParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type.");
  }
}

bool IsNistCurve(EciesParameters::CurveType curve) {
  return curve == EciesParameters::CurveType::kNistP256 ||
         curve == EciesParameters::CurveType::kNistP384 ||
         curve == EciesParameters::CurveType::kNistP521;
}

util::StatusOr<EciesParameters::CurveType> FromProtoCurveType(
    EllipticCurveType curve) {
  switch (curve) {
    case EllipticCurveType::NIST_P256:
      return EciesParameters::CurveType::kNistP256;
    case EllipticCurveType::NIST_P384:
      return EciesParameters::CurveType::kNistP384;
    case EllipticCurveType::NIST_P521:
      return EciesParameters::CurveType::kNistP521;
    case EllipticCurveType::CURVE25519:
      return EciesParameters::CurveType::kX25519;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EciesParameters::CurveType.");
  }
}

util::StatusOr<EllipticCurveType> ToProtoCurveType(
    EciesParameters::CurveType curve) {
  switch (curve) {
    case EciesParameters::CurveType::kNistP256:
      return EllipticCurveType::NIST_P256;
    case EciesParameters::CurveType::kNistP384:
      return EllipticCurveType::NIST_P384;
    case EciesParameters::CurveType::kNistP521:
      return EllipticCurveType::NIST_P521;
    case EciesParameters::CurveType::kX25519:
      return EllipticCurveType::CURVE25519;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine curve type.");
  }
}

util::StatusOr<EciesParameters::HashType> FromProtoHashType(HashType hash) {
  switch (hash) {
    case HashType::SHA1:
      return EciesParameters::HashType::kSha1;
    case HashType::SHA224:
      return EciesParameters::HashType::kSha224;
    case HashType::SHA256:
      return EciesParameters::HashType::kSha256;
    case HashType::SHA384:
      return EciesParameters::HashType::kSha384;
    case HashType::SHA512:
      return EciesParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EciesParameters::HashType.");
  }
}

util::StatusOr<HashType> ToProtoHashType(EciesParameters::HashType hash) {
  switch (hash) {
    case EciesParameters::HashType::kSha1:
      return HashType::SHA1;
    case EciesParameters::HashType::kSha224:
      return HashType::SHA224;
    case EciesParameters::HashType::kSha256:
      return HashType::SHA256;
    case EciesParameters::HashType::kSha384:
      return HashType::SHA384;
    case EciesParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine hash type.");
  }
}

util::StatusOr<EciesParameters::PointFormat> FromProtoPointFormat(
    EcPointFormat format) {
  switch (format) {
    case EcPointFormat::COMPRESSED:
      return EciesParameters::PointFormat::kCompressed;
    case EcPointFormat::UNCOMPRESSED:
      return EciesParameters::PointFormat::kUncompressed;
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return EciesParameters::PointFormat::kLegacyUncompressed;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EciesParameters::PointFormat.");
  }
}

util::StatusOr<EcPointFormat> ToProtoPointFormat(
    EciesParameters::PointFormat format) {
  switch (format) {
    case EciesParameters::PointFormat::kCompressed:
      return EcPointFormat::COMPRESSED;
    case EciesParameters::PointFormat::kUncompressed:
      return EcPointFormat::UNCOMPRESSED;
    case EciesParameters::PointFormat::kLegacyUncompressed:
      return EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine point format.");
  }
}

util::StatusOr<EciesParameters::DemId> FromProtoDemParams(
    EciesAeadDemParams proto_dem_params) {
  if (!proto_dem_params.has_aead_dem()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing EciesAeadDemParams.aead_dem field.");
  }
  if (proto_dem_params.aead_dem().type_url() ==
      "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    AesGcmKeyFormat aes_gcm_key_format;
    if (!aes_gcm_key_format.ParseFromString(
            proto_dem_params.aead_dem().value())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid AES-GCM key format.");
    }
    if (aes_gcm_key_format.key_size() == 16) {
      return EciesParameters::DemId::kAes128GcmRaw;
    }
    if (aes_gcm_key_format.key_size() == 32) {
      return EciesParameters::DemId::kAes256GcmRaw;
    }
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid AES-GCM key length for DEM.");
  }
  if (proto_dem_params.aead_dem().type_url() ==
      "type.googleapis.com/google.crypto.tink.AesSivKey") {
    AesSivKeyFormat aes_siv_key_format;
    if (!aes_siv_key_format.ParseFromString(
            proto_dem_params.aead_dem().value())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid AES-SIV key format.");
    }
    if (aes_siv_key_format.key_size() == 64) {
      return EciesParameters::DemId::kAes256SivRaw;
    }
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid AES-SIV key length for DEM.");
  }
  return util::Status(absl::StatusCode::kInvalidArgument,
                      "Unable to convert proto DEM params to DEM id.");
}

EciesAeadDemParams CreateEciesAeadDemParams(
    absl::string_view type_url, const std::string& serialized_key_format) {
  EciesAeadDemParams dem_params;
  KeyTemplate key_template;
  key_template.set_type_url(type_url);
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  *key_template.mutable_value() = serialized_key_format;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

util::StatusOr<EciesAeadDemParams> ToProtoDemParams(
    EciesParameters::DemId dem_id) {
  if (dem_id == EciesParameters::DemId::kAes128GcmRaw ||
      dem_id == EciesParameters::DemId::kAes256GcmRaw) {
    int key_size = (dem_id == EciesParameters::DemId::kAes128GcmRaw) ? 16 : 32;
    AesGcmKeyFormat format;
    format.set_version(0);
    format.set_key_size(key_size);
    return CreateEciesAeadDemParams(
        "type.googleapis.com/google.crypto.tink.AesGcmKey",
        format.SerializeAsString());
  }
  if (dem_id == EciesParameters::DemId::kAes256SivRaw) {
    AesSivKeyFormat format;
    format.set_version(0);
    format.set_key_size(64);
    return CreateEciesAeadDemParams(
        "type.googleapis.com/google.crypto.tink.AesSivKey",
        format.SerializeAsString());
  }
  return util::Status(absl::StatusCode::kInvalidArgument,
                      "Unable to convert DEM id to proto DEM params.");
}

util::StatusOr<EciesParameters> ToParameters(
    OutputPrefixType output_prefix_type, EciesAeadHkdfParams params) {
  if (!params.has_kem_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing EciesAeadHkdfParams.kem_params field.");
  }
  if (!params.has_dem_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing EciesAeadHkdfParams.dem_params field.");
  }

  util::StatusOr<EciesParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<EciesParameters::CurveType> curve_type =
      FromProtoCurveType(params.kem_params().curve_type());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  util::StatusOr<EciesParameters::HashType> hash_type =
      FromProtoHashType(params.kem_params().hkdf_hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<EciesParameters::DemId> dem_id =
      FromProtoDemParams(params.dem_params());
  if (!dem_id.ok()) {
    return dem_id.status();
  }

  EciesParameters::Builder builder = EciesParameters::Builder()
                                         .SetVariant(*variant)
                                         .SetCurveType(*curve_type)
                                         .SetHashType(*hash_type)
                                         .SetDemId(*dem_id);

  if (IsNistCurve(*curve_type)) {
    util::StatusOr<EciesParameters::PointFormat> point_format =
        FromProtoPointFormat(params.ec_point_format());
    if (!point_format.ok()) {
      return point_format.status();
    }
    builder.SetNistCurvePointFormat(*point_format);
  }

  if (!params.kem_params().hkdf_salt().empty()) {
    builder.SetSalt(params.kem_params().hkdf_salt());
  }

  return builder.Build();
}

util::StatusOr<EciesAeadHkdfParams> FromParameters(
    const EciesParameters& parameters) {
  util::StatusOr<EllipticCurveType> curve_type =
      ToProtoCurveType(parameters.GetCurveType());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<EciesAeadDemParams> dem_params =
      ToProtoDemParams(parameters.GetDemId());
  if (!dem_params.ok()) {
    return dem_params.status();
  }

  EciesAeadHkdfParams params;
  *params.mutable_dem_params() = *dem_params;
  EciesHkdfKemParams* kem_params = params.mutable_kem_params();
  kem_params->set_curve_type(*curve_type);
  kem_params->set_hkdf_hash_type(*hash_type);
  if (parameters.GetSalt().has_value()) {
    kem_params->set_hkdf_salt(*parameters.GetSalt());
  }
  if (parameters.GetNistCurvePointFormat().has_value()) {
    util::StatusOr<EcPointFormat> ec_point_format =
        ToProtoPointFormat(*parameters.GetNistCurvePointFormat());
    if (!ec_point_format.ok()) {
      return ec_point_format.status();
    }
    params.set_ec_point_format(*ec_point_format);
  } else {
    // Must be X25519, so set to the compressed format.
    params.set_ec_point_format(EcPointFormat::COMPRESSED);
  }

  return params;
}

util::StatusOr<EciesPublicKey> ToPublicKey(
    const EciesParameters& parameters, const EciesAeadHkdfPublicKey& proto_key,
    absl::optional<int> id_requirement) {
  if (IsNistCurve(parameters.GetCurveType())) {
    EcPoint point(BigInteger(proto_key.x()), BigInteger(proto_key.y()));
    return EciesPublicKey::CreateForNistCurve(parameters, point, id_requirement,
                                              GetPartialKeyAccess());
  }
  return EciesPublicKey::CreateForCurveX25519(
      parameters, proto_key.x(), id_requirement, GetPartialKeyAccess());
}

util::StatusOr<int> GetEncodingLength(EciesParameters::CurveType curve) {
  // Encode EC field elements with extra leading zero byte for compatibility
  // with Java BigInteger decoding (b/264525021).
  switch (curve) {
    case EciesParameters::CurveType::kNistP256:
      return 33;
    case EciesParameters::CurveType::kNistP384:
      return 49;
    case EciesParameters::CurveType::kNistP521:
      return 67;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Cannot determine encoding length for curve.");
  }
}

util::StatusOr<EciesAeadHkdfPublicKey> FromPublicKey(
    const EciesAeadHkdfParams& params, const EciesPublicKey& public_key) {
  EciesAeadHkdfPublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = params;
  if (public_key.GetNistCurvePoint(GetPartialKeyAccess()).has_value()) {
    EcPoint point = *public_key.GetNistCurvePoint(GetPartialKeyAccess());
    util::StatusOr<int> encoding_length =
        GetEncodingLength(public_key.GetParameters().GetCurveType());
    if (!encoding_length.ok()) {
      return encoding_length.status();
    }
    util::StatusOr<std::string> x = internal::GetValueOfFixedLength(
        point.GetX().GetValue(), *encoding_length);
    if (!x.ok()) {
      return x.status();
    }
    util::StatusOr<std::string> y = internal::GetValueOfFixedLength(
        point.GetY().GetValue(), *encoding_length);
    if (!y.ok()) {
      return y.status();
    }
    proto_key.set_x(*x);
    proto_key.set_y(*y);
  } else {
    if (!public_key.GetX25519CurvePointBytes(GetPartialKeyAccess())
             .has_value()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "X25519 public key missing point bytes.");
    }
    proto_key.set_x(
        *public_key.GetX25519CurvePointBytes(GetPartialKeyAccess()));
    proto_key.set_y("");
  }
  return proto_key;
}

util::StatusOr<EciesParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EciesParameters.");
  }

  EciesAeadHkdfKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EciesAeadHkdfKeyFormat proto.");
  }
  if (!proto_key_format.has_params()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "EciesAeadHkdfKeyFormat proto is missing params field.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.params());
}

util::StatusOr<EciesPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EciesAeadHkdfPublicKey.");
  }

  EciesAeadHkdfPublicKey proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EciesAeadHkdfPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Only version 0 keys are accepted for EciesAeadHkdfPublicKey proto.");
  }

  util::StatusOr<EciesParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, proto_key, serialization.IdRequirement());
}

util::StatusOr<EciesPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EciesAeadHkdfPrivateKey.");
  }
  EciesAeadHkdfPrivateKey proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EciesAeadHkdfPrivateKey proto.");
  }
  if (proto_key.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Only version 0 keys are accepted for EciesAeadHkdfPrivateKey proto.");
  }

  util::StatusOr<EciesParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<EciesParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<EciesPublicKey> public_key = ToPublicKey(
      *parameters, proto_key.public_key(), serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  if (IsNistCurve(parameters->GetCurveType())) {
    return EciesPrivateKey::CreateForNistCurve(
        *public_key, RestrictedBigInteger(proto_key.key_value(), *token),
        GetPartialKeyAccess());
  }

  return EciesPrivateKey::CreateForCurveX25519(
      *public_key, RestrictedData(proto_key.key_value(), *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const EciesParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<EciesAeadHkdfParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  EciesAeadHkdfKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const EciesPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<EciesAeadHkdfParams> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<EciesAeadHkdfPublicKey> proto_key =
      FromPublicKey(*params, key);
  if (!proto_key.ok()) {
    return proto_key.status();
  }

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key->SerializeAsString(), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const EciesPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<EciesAeadHkdfParams> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<EciesAeadHkdfPublicKey> proto_public_key =
      FromPublicKey(*params, key.GetPublicKey());
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  EciesAeadHkdfPrivateKey proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = *proto_public_key;
  if (IsNistCurve(key.GetPublicKey().GetParameters().GetCurveType())) {
    util::StatusOr<int> encoding_length =
        GetEncodingLength(key.GetPublicKey().GetParameters().GetCurveType());
    if (!encoding_length.ok()) {
      return encoding_length.status();
    }
    absl::optional<RestrictedBigInteger> secret =
        key.GetNistPrivateKeyValue(GetPartialKeyAccess());
    if (!secret.has_value()) {
      return util::Status(
          absl::StatusCode::kInternal,
          "NIST private key is missing NIST private key value.");
    }
    util::StatusOr<std::string> key_value = internal::GetValueOfFixedLength(
        secret->GetSecret(InsecureSecretKeyAccess::Get()), *encoding_length);
    if (!key_value.ok()) {
      return key_value.status();
    }
    proto_private_key.set_key_value(*key_value);
  } else {
    absl::optional<RestrictedData> secret =
        key.GetX25519PrivateKeyBytes(GetPartialKeyAccess());
    if (!secret.has_value()) {
      return util::Status(
          absl::StatusCode::kInternal,
          "X25519 private key is missing X25519 private key bytes.");
    }
    proto_private_key.set_key_value(
        secret->GetSecret(InsecureSecretKeyAccess::Get()));
  }

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

EciesProtoParametersParserImpl* EciesProtoParametersParser() {
  static auto* parser =
      new EciesProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

EciesProtoParametersSerializerImpl* EciesProtoParametersSerializer() {
  static auto* serializer = new EciesProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

EciesProtoPublicKeyParserImpl* EciesProtoPublicKeyParser() {
  static auto* parser =
      new EciesProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

EciesProtoPublicKeySerializerImpl* EciesProtoPublicKeySerializer() {
  static auto* serializer =
      new EciesProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

EciesProtoPrivateKeyParserImpl* EciesProtoPrivateKeyParser() {
  static auto* parser =
      new EciesProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

EciesProtoPrivateKeySerializerImpl* EciesProtoPrivateKeySerializer() {
  static auto* serializer =
      new EciesProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

util::Status RegisterEciesProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(EciesProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(EciesProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(EciesProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(EciesProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(EciesProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(EciesProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
