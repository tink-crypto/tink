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

#include "tink/signature/rsa_ssa_pss_proto_serialization.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
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
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPssKeyFormat;
using ::google::crypto::tink::RsaSsaPssParams;

using RsaSsaPssProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   RsaSsaPssParameters>;
using RsaSsaPssProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<RsaSsaPssParameters,
                                       internal::ProtoParametersSerialization>;
using RsaSsaPssProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPssPublicKey>;
using RsaSsaPssProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPssPublicKey,
                                internal::ProtoKeySerialization>;
using RsaSsaPssProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPssPrivateKey>;
using RsaSsaPssProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPssPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";

util::StatusOr<RsaSsaPssParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return RsaSsaPssParameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return RsaSsaPssParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return RsaSsaPssParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return RsaSsaPssParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine RsaSsaPssParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    RsaSsaPssParameters::Variant variant) {
  switch (variant) {
    case RsaSsaPssParameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case RsaSsaPssParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case RsaSsaPssParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case RsaSsaPssParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type.");
  }
}

util::StatusOr<RsaSsaPssParameters::HashType> ToEnumHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA256:
      return RsaSsaPssParameters::HashType::kSha256;
    case HashType::SHA384:
      return RsaSsaPssParameters::HashType::kSha384;
    case HashType::SHA512:
      return RsaSsaPssParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    RsaSsaPssParameters::HashType hash_type) {
  switch (hash_type) {
    case RsaSsaPssParameters::HashType::kSha256:
      return HashType::SHA256;
    case RsaSsaPssParameters::HashType::kSha384:
      return HashType::SHA384;
    case RsaSsaPssParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine RsaSsaPssParameters::HashType");
  }
}

util::StatusOr<RsaSsaPssParameters> ToParameters(
    OutputPrefixType output_prefix_type, const RsaSsaPssParams& params,
    int modulus_size_in_bits, const BigInteger& public_exponent) {
  util::StatusOr<RsaSsaPssParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<RsaSsaPssParameters::HashType> sig_hash_type =
      ToEnumHashType(params.sig_hash());
  if (!sig_hash_type.ok()) {
    return sig_hash_type.status();
  }

  util::StatusOr<RsaSsaPssParameters::HashType> mgf1_hash_type =
      ToEnumHashType(params.sig_hash());
  if (!mgf1_hash_type.ok()) {
    return mgf1_hash_type.status();
  }

  return RsaSsaPssParameters::Builder()
      .SetVariant(*variant)
      .SetSigHashType(*sig_hash_type)
      .SetMgf1HashType(*mgf1_hash_type)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .SetSaltLengthInBytes(params.salt_length())
      .Build();
}

util::StatusOr<RsaSsaPssParams> FromParameters(RsaSsaPssParameters parameters) {
  util::StatusOr<HashType> sig_hash_type =
      ToProtoHashType(parameters.GetSigHashType());
  if (!sig_hash_type.ok()) {
    return sig_hash_type.status();
  }

  util::StatusOr<HashType> mgf1_hash_type =
      ToProtoHashType(parameters.GetMgf1HashType());
  if (!mgf1_hash_type.ok()) {
    return mgf1_hash_type.status();
  }

  RsaSsaPssParams params;
  params.set_sig_hash(*sig_hash_type);
  params.set_mgf1_hash(*mgf1_hash_type);
  params.set_salt_length(parameters.GetSaltLengthInBytes());

  return params;
}

util::StatusOr<RsaSsaPssParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPssParameters.");
  }

  RsaSsaPssKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPssKeyFormat proto");
  }
  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "RsaSsaPssKeyFormat proto is missing params field.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.params(),
                      proto_key_format.modulus_size_in_bits(),
                      BigInteger(proto_key_format.public_exponent()));
}

util::StatusOr<RsaSsaPssPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPssPublicKey.");
  }

  google::crypto::tink::RsaSsaPssPublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPssPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;
  util::StatusOr<RsaSsaPssParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.params(),
                   modulus_size_in_bits, BigInteger(proto_key.e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  return RsaSsaPssPublicKey::Create(*parameters, modulus,
                                    serialization.IdRequirement(),
                                    GetPartialKeyAccess());
}

util::StatusOr<RsaSsaPssPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPssPrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  google::crypto::tink::RsaSsaPssPrivateKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPssPrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key.public_key().n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  util::StatusOr<RsaSsaPssParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key.public_key().params(),
      modulus_size_in_bits, BigInteger(proto_key.public_key().e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus, serialization.IdRequirement(),
      GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return RsaSsaPssPrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(RestrictedBigInteger(proto_key.p(), *token))
      .SetPrimeQ(RestrictedBigInteger(proto_key.q(), *token))
      .SetPrimeExponentP(RestrictedBigInteger(proto_key.dp(), *token))
      .SetPrimeExponentQ(RestrictedBigInteger(proto_key.dq(), *token))
      .SetPrivateExponent(RestrictedBigInteger(proto_key.d(), *token))
      .SetCrtCoefficient(RestrictedBigInteger(proto_key.crt(), *token))
      .Build(GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const RsaSsaPssParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<RsaSsaPssParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }

  RsaSsaPssKeyFormat proto_key_format;
  proto_key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  // OSS proto library complains if input is not converted to a string.
  proto_key_format.set_public_exponent(
      std::string(parameters.GetPublicExponent().GetValue()));
  *proto_key_format.mutable_params() = *params;

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPssPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RsaSsaPssParams> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  google::crypto::tink::RsaSsaPssPublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  // OSS proto library complains if input is not converted to a string.
  proto_key.set_n(
      std::string(key.GetModulus(GetPartialKeyAccess()).GetValue()));
  proto_key.set_e(
      std::string(key.GetParameters().GetPublicExponent().GetValue()));

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
    const RsaSsaPssPrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<RsaSsaPssParams> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  google::crypto::tink::RsaSsaPssPublicKey proto_public_key;
  proto_public_key.set_version(0);
  *proto_public_key.mutable_params() = *params;
  // OSS proto library complains if input is not converted to a string.
  proto_public_key.set_n(std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue()));
  proto_public_key.set_e(std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue()));

  google::crypto::tink::RsaSsaPssPrivateKey proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = proto_public_key;
  // OSS proto library complains if input is not converted to a string.
  proto_private_key.set_p(
      std::string(key.GetPrimeP(GetPartialKeyAccess()).GetSecret(*token)));
  proto_private_key.set_q(
      std::string(key.GetPrimeQ(GetPartialKeyAccess()).GetSecret(*token)));
  proto_private_key.set_dp(
      std::string(key.GetPrimeExponentP().GetSecret(*token)));
  proto_private_key.set_dq(
      std::string(key.GetPrimeExponentQ().GetSecret(*token)));
  proto_private_key.set_d(
      std::string(key.GetPrivateExponent().GetSecret(*token)));
  proto_private_key.set_crt(
      std::string(key.GetCrtCoefficient().GetSecret(*token)));

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

RsaSsaPssProtoParametersParserImpl* RsaSsaPssProtoParametersParser() {
  static auto* parser =
      new RsaSsaPssProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

RsaSsaPssProtoParametersSerializerImpl* RsaSsaPssProtoParametersSerializer() {
  static auto* serializer = new RsaSsaPssProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

RsaSsaPssProtoPublicKeyParserImpl* RsaSsaPssProtoPublicKeyParser() {
  static auto* parser =
      new RsaSsaPssProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

RsaSsaPssProtoPublicKeySerializerImpl* RsaSsaPssProtoPublicKeySerializer() {
  static auto* serializer =
      new RsaSsaPssProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

RsaSsaPssProtoPrivateKeyParserImpl* RsaSsaPssProtoPrivateKeyParser() {
  static auto* parser =
      new RsaSsaPssProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

RsaSsaPssProtoPrivateKeySerializerImpl* RsaSsaPssProtoPrivateKeySerializer() {
  static auto* serializer =
      new RsaSsaPssProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

util::Status RegisterRsaSsaPssProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(RsaSsaPssProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(RsaSsaPssProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPssProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(RsaSsaPssProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPssProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(RsaSsaPssProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
