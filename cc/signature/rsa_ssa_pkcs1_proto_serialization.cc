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
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::RsaSsaPkcs1Params;

using RsaSsaPkcs1ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   RsaSsaPkcs1Parameters>;
using RsaSsaPkcs1ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<RsaSsaPkcs1Parameters,
                                       internal::ProtoParametersSerialization>;
using RsaSsaPkcs1ProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPkcs1PublicKey>;
using RsaSsaPkcs1ProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPkcs1PublicKey,
                                internal::ProtoKeySerialization>;
using RsaSsaPkcs1ProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPkcs1PrivateKey>;
using RsaSsaPkcs1ProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPkcs1PrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

util::StatusOr<RsaSsaPkcs1Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return RsaSsaPkcs1Parameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return RsaSsaPkcs1Parameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return RsaSsaPkcs1Parameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return RsaSsaPkcs1Parameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine RsaSsaPkcs1Parameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    RsaSsaPkcs1Parameters::Variant variant) {
  switch (variant) {
    case RsaSsaPkcs1Parameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case RsaSsaPkcs1Parameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case RsaSsaPkcs1Parameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case RsaSsaPkcs1Parameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type.");
  }
}

util::StatusOr<RsaSsaPkcs1Parameters::HashType> ToEnumHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA256:
      return RsaSsaPkcs1Parameters::HashType::kSha256;
    case HashType::SHA384:
      return RsaSsaPkcs1Parameters::HashType::kSha384;
    case HashType::SHA512:
      return RsaSsaPkcs1Parameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    RsaSsaPkcs1Parameters::HashType hash_type) {
  switch (hash_type) {
    case RsaSsaPkcs1Parameters::HashType::kSha256:
      return HashType::SHA256;
    case RsaSsaPkcs1Parameters::HashType::kSha384:
      return HashType::SHA384;
    case RsaSsaPkcs1Parameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine RsaSsaPkcs1Parameters::HashType");
  }
}

util::StatusOr<RsaSsaPkcs1Parameters> ToParameters(
    OutputPrefixType output_prefix_type, const RsaSsaPkcs1Params& params,
    int modulus_size_in_bits, const BigInteger& public_exponent) {
  util::StatusOr<RsaSsaPkcs1Parameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<RsaSsaPkcs1Parameters::HashType> hash_type =
      ToEnumHashType(params.hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return RsaSsaPkcs1Parameters::Builder()
      .SetVariant(*variant)
      .SetHashType(*hash_type)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .Build();
}

util::StatusOr<RsaSsaPkcs1Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPkcs1Parameters.");
  }

  RsaSsaPkcs1KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPkcs1KeyFormat proto");
  }
  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "RsaSsaPkcs1KeyFormat proto is missing params field.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.params(),
                      proto_key_format.modulus_size_in_bits(),
                      BigInteger(proto_key_format.public_exponent()));
}

util::StatusOr<RsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPkcs1PublicKey.");
  }

  google::crypto::tink::RsaSsaPkcs1PublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPkcs1PublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.params(),
                   modulus_size_in_bits, BigInteger(proto_key.e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  return RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                      serialization.IdRequirement(),
                                      GetPartialKeyAccess());
}

util::StatusOr<RsaSsaPkcs1PrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPkcs1PrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  google::crypto::tink::RsaSsaPkcs1PrivateKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPkcs1PrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key.public_key().n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  util::StatusOr<RsaSsaPkcs1Parameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key.public_key().params(),
      modulus_size_in_bits, BigInteger(proto_key.public_key().e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   serialization.IdRequirement(),
                                   GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return RsaSsaPkcs1PrivateKey::Builder()
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
    const RsaSsaPkcs1Parameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1Params params;
  params.set_hash_type(*hash_type);
  RsaSsaPkcs1KeyFormat proto_key_format;
  proto_key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  // OSS proto library complains if input is not converted to a string.
  proto_key_format.set_public_exponent(
      std::string(parameters.GetPublicExponent().GetValue()));
  *proto_key_format.mutable_params() = params;

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPkcs1PublicKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<HashType> hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1Params params;
  params.set_hash_type(*hash_type);

  google::crypto::tink::RsaSsaPkcs1PublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = params;
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
    const RsaSsaPkcs1PrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(key.GetPublicKey().GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1Params params;
  params.set_hash_type(*hash_type);

  google::crypto::tink::RsaSsaPkcs1PublicKey proto_public_key;
  proto_public_key.set_version(0);
  *proto_public_key.mutable_params() = params;
  // OSS proto library complains if input is not converted to a string.
  proto_public_key.set_n(std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue()));
  proto_public_key.set_e(std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue()));

  google::crypto::tink::RsaSsaPkcs1PrivateKey proto_private_key;
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

RsaSsaPkcs1ProtoParametersParserImpl* RsaSsaPkcs1ProtoParametersParser() {
  static auto* parser = new RsaSsaPkcs1ProtoParametersParserImpl(
      kPrivateTypeUrl, ParseParameters);
  return parser;
}

RsaSsaPkcs1ProtoParametersSerializerImpl*
RsaSsaPkcs1ProtoParametersSerializer() {
  static auto* serializer = new RsaSsaPkcs1ProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

RsaSsaPkcs1ProtoPublicKeyParserImpl* RsaSsaPkcs1ProtoPublicKeyParser() {
  static auto* parser =
      new RsaSsaPkcs1ProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

RsaSsaPkcs1ProtoPublicKeySerializerImpl* RsaSsaPkcs1ProtoPublicKeySerializer() {
  static auto* serializer =
      new RsaSsaPkcs1ProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

RsaSsaPkcs1ProtoPrivateKeyParserImpl* RsaSsaPkcs1ProtoPrivateKeyParser() {
  static auto* parser = new RsaSsaPkcs1ProtoPrivateKeyParserImpl(
      kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

RsaSsaPkcs1ProtoPrivateKeySerializerImpl*
RsaSsaPkcs1ProtoPrivateKeySerializer() {
  static auto* serializer =
      new RsaSsaPkcs1ProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

util::Status RegisterRsaSsaPkcs1ProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(RsaSsaPkcs1ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(RsaSsaPkcs1ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPkcs1ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(RsaSsaPkcs1ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPkcs1ProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(RsaSsaPkcs1ProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
