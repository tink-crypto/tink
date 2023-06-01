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

#include "tink/mac/aes_cmac_proto_serialization.h"

#include <string>

#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_cmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::AesCmacKeyFormat;
using ::google::crypto::tink::AesCmacParams;
using ::google::crypto::tink::OutputPrefixType;

using AesCmacProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCmacParameters>;
using AesCmacProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCmacParameters,
                                       internal::ProtoParametersSerialization>;
using AesCmacProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesCmacKey>;
using AesCmacProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesCmacKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacKey";

util::StatusOr<AesCmacParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::CRUNCHY:
      return AesCmacParameters::Variant::kCrunchy;
    case OutputPrefixType::LEGACY:
      return AesCmacParameters::Variant::kLegacy;
    case OutputPrefixType::RAW:
      return AesCmacParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesCmacParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesCmacParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesCmacParameters::Variant variant) {
  switch (variant) {
    case AesCmacParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesCmacParameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case AesCmacParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesCmacParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<AesCmacParameters> ParseParameters(
    internal::ProtoParametersSerialization serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCmacParameters.");
  }

  AesCmacKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCmacKeyFormat proto");
  }

  util::StatusOr<AesCmacParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  return AesCmacParameters::Create(proto_key_format.key_size(),
                                   proto_key_format.params().tag_size(),
                                   *variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    AesCmacParameters parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  AesCmacParams proto_params;
  proto_params.set_tag_size(parameters.CryptographicTagSizeInBytes());
  AesCmacKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  *proto_key_format.mutable_params() = proto_params;

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<AesCmacKey> ParseKey(
    internal::ProtoKeySerialization serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCmacKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  google::crypto::tink::AesCmacKey proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  // OSS proto library complains if input is not converted to a string.
  if (!proto_key.ParseFromString(
          std::string(restricted_data.GetSecret(*token)))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCmacKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesCmacParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  util::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      proto_key.key_value().length(), proto_key.params().tag_size(), *variant);
  if (!parameters.ok()) return parameters.status();

  util::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *parameters, RestrictedData(proto_key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!key.ok()) return key.status();

  return *key;
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    AesCmacKey key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  AesCmacParams proto_params;
  proto_params.set_tag_size(key.GetParameters().CryptographicTagSizeInBytes());
  google::crypto::tink::AesCmacKey proto_key;
  *proto_key.mutable_params() = proto_params;
  proto_key.set_version(0);
  // OSS proto library complains if input is not converted to a string.
  proto_key.set_key_value(std::string(restricted_input->GetSecret(*token)));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  RestrictedData restricted_output =
      RestrictedData(proto_key.SerializeAsString(), *token);
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      *output_prefix_type, key.GetIdRequirement());
}

AesCmacProtoParametersParserImpl* AesCmacProtoParametersParser() {
  static auto* parser =
      new AesCmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesCmacProtoParametersSerializerImpl* AesCmacProtoParametersSerializer() {
  static auto* serializer =
      new AesCmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesCmacProtoKeyParserImpl* AesCmacProtoKeyParser() {
  static auto* parser = new AesCmacProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCmacProtoKeySerializerImpl* AesCmacProtoKeySerializer() {
  static auto* serializer = new AesCmacProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesCmacProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesCmacProtoParametersParser());
  if (!status.ok()) return status;

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(AesCmacProtoParametersSerializer());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesCmacProtoKeyParser());
  if (!status.ok()) return status;

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesCmacProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
