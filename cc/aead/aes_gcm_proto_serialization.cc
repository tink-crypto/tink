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

#include "tink/aead/aes_gcm_proto_serialization.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
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
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using AesGcmProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesGcmParameters>;
using AesGcmProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesGcmParameters,
                                       internal::ProtoParametersSerialization>;
using AesGcmProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesGcmKey>;
using AesGcmProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesGcmKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmKey";

util::StatusOr<AesGcmParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
       ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return AesGcmParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return AesGcmParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesGcmParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesGcmParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesGcmParameters::Variant variant) {
  switch (variant) {
    case AesGcmParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesGcmParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesGcmParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

// Legacy Tink AES-GCM key proto format assumes 12-byte random IVs and 16-byte
// tags.
util::Status ValidateParamsForProto(const AesGcmParameters& params) {
  if (params.IvSizeInBytes() != 12) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Tink currently restricts AES-GCM IV size to 12 bytes.");
  }
  if (params.TagSizeInBytes() != 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Tink currently restricts AES-GCM tag size to 16 bytes.");
  }
  return util::OkStatus();
}

util::StatusOr<AesGcmParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesGcmParameters.");
  }

  AesGcmKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesGcmKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesGcmParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  // Legacy Tink AES-GCM key proto format assumes 12-byte random IVs and 16-byte
  // tags.
  return AesGcmParameters::Builder()
      .SetVariant(*variant)
      .SetKeySizeInBytes(proto_key_format.key_size())
      .SetIvSizeInBytes(12)
      .SetTagSizeInBytes(16)
      .Build();
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesGcmParameters& parameters) {
  util::Status valid_params = ValidateParamsForProto(parameters);
  if (!valid_params.ok()) return valid_params;

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  AesGcmKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<AesGcmKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesGcmKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  SecretProto<google::crypto::tink::AesGcmKey> proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  if (!proto_key->ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesGcmKey proto");
  }
  if (proto_key->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesGcmParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  // Legacy AES-GCM key proto format assumes 12-byte random IVs and 16-byte
  // tags.
  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(*variant)
          .SetKeySizeInBytes(proto_key->key_value().length())
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  if (!parameters.ok()) return parameters.status();

  return AesGcmKey::Create(
      *parameters, RestrictedData(proto_key->key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesGcmKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::Status valid_params = ValidateParamsForProto(key.GetParameters());
  if (!valid_params.ok()) return valid_params;

  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  SecretProto<google::crypto::tink::AesGcmKey> proto_key;
  proto_key->set_version(0);
  proto_key->set_key_value(restricted_input->GetSecret(*token));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(util::SecretDataAsStringView(*serialized_key), *token);
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      *output_prefix_type, key.GetIdRequirement());
}

AesGcmProtoParametersParserImpl* AesGcmProtoParametersParser() {
  static auto* parser =
      new AesGcmProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesGcmProtoParametersSerializerImpl* AesGcmProtoParametersSerializer() {
  static auto* serializer =
      new AesGcmProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesGcmProtoKeyParserImpl* AesGcmProtoKeyParser() {
  static auto* parser = new AesGcmProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesGcmProtoKeySerializerImpl* AesGcmProtoKeySerializer() {
  static auto* serializer = new AesGcmProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesGcmProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesGcmProtoParametersParser());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(AesGcmProtoParametersSerializer());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesGcmProtoKeyParser());
  if (!status.ok()) return status;

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesGcmProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
