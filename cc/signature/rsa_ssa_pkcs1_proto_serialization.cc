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
#include "tink/big_integer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::RsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::RsaSsaPkcs1Params;

using RsaSsaPkcs1ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   RsaSsaPkcs1Parameters>;
using RsaSsaPkcs1ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<RsaSsaPkcs1Parameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";

util::StatusOr<RsaSsaPkcs1Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
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

  util::StatusOr<RsaSsaPkcs1Parameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<RsaSsaPkcs1Parameters::HashType> hash_type =
      ToEnumHashType(proto_key_format.params().hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return RsaSsaPkcs1Parameters::Builder()
      .SetVariant(*variant)
      .SetHashType(*hash_type)
      .SetModulusSizeInBits(proto_key_format.modulus_size_in_bits())
      .SetPublicExponent(BigInteger(proto_key_format.public_exponent()))
      .Build();
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
  proto_key_format.set_public_exponent(
      std::string(parameters.GetPublicExponent().GetValue()));
  *proto_key_format.mutable_params() = params;

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
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

}  // namespace

util::Status RegisterRsaSsaPkcs1ProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(RsaSsaPkcs1ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(RsaSsaPkcs1ProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
