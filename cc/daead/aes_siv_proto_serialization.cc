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

#include "tink/daead/aes_siv_proto_serialization.h"

#include <string>

#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_siv.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using AesSivProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesSivParameters>;
using AesSivProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesSivParameters,
                                       internal::ProtoParametersSerialization>;
using AesSivProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesSivKey>;
using AesSivProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesSivKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesSivKey";

util::StatusOr<AesSivParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return AesSivParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return AesSivParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesSivParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesSivParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesSivParameters::Variant variant) {
  switch (variant) {
    case AesSivParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesSivParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesSivParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<AesSivParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesSivParameters.");
  }

  AesSivKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesSivKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesSivParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  return AesSivParameters::Create(proto_key_format.key_size(), *variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesSivParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  AesSivKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<AesSivKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesSivKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  google::crypto::tink::AesSivKey proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  // OSS proto library complains if input is not converted to a string.
  if (!proto_key.ParseFromString(
          std::string(restricted_data.GetSecret(*token)))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesSivKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesSivParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  util::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(proto_key.key_value().length(), *variant);
  if (!parameters.ok()) return parameters.status();

  return AesSivKey::Create(
      *parameters, RestrictedData(proto_key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesSivKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  google::crypto::tink::AesSivKey proto_key;
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

AesSivProtoParametersParserImpl* AesSivProtoParametersParser() {
  static auto* parser =
      new AesSivProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesSivProtoParametersSerializerImpl* AesSivProtoParametersSerializer() {
  static auto* serializer =
      new AesSivProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesSivProtoKeyParserImpl* AesSivProtoKeyParser() {
  static auto* parser = new AesSivProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesSivProtoKeySerializerImpl* AesSivProtoKeySerializer() {
  static auto* serializer = new AesSivProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesSivProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesSivProtoParametersParser());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(AesSivProtoParametersSerializer());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesSivProtoKeyParser());
  if (!status.ok()) return status;

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesSivProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
