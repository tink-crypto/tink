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

#include "tink/aead/aes_eax_proto_serialization.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
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
#include "proto/aes_eax.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::AesEaxKeyFormat;
using ::google::crypto::tink::AesEaxParams;
using ::google::crypto::tink::OutputPrefixType;

using AesEaxProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesEaxParameters>;
using AesEaxProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesEaxParameters,
                                       internal::ProtoParametersSerialization>;
using AesEaxProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesEaxKey>;
using AesEaxProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesEaxKey, internal::ProtoKeySerialization>;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesEaxKey";

util::StatusOr<AesEaxParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return AesEaxParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return AesEaxParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesEaxParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesEaxParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesEaxParameters::Variant variant) {
  switch (variant) {
    case AesEaxParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesEaxParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesEaxParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<AesEaxParams> GetProtoParams(
    const AesEaxParameters& parameters) {
  // Legacy Tink AES-EAX key proto format assumes 16-byte tags.
  if (parameters.GetTagSizeInBytes() != 16) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Tink currently restricts AES-EAX tag size to 16 bytes.");
  }

  AesEaxParams params;
  params.set_iv_size(parameters.GetIvSizeInBytes());

  return params;
}

util::StatusOr<AesEaxParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Wrong type URL when parsing AesEaxParameters: ",
                     serialization.GetKeyTemplate().type_url()));
  }

  AesEaxKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesEaxKeyFormat proto");
  }

  util::StatusOr<AesEaxParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  // Legacy Tink AES-EAX key proto format assumes 16-byte tags only.
  return AesEaxParameters::Builder()
      .SetVariant(*variant)
      .SetKeySizeInBytes(proto_key_format.key_size())
      .SetIvSizeInBytes(proto_key_format.params().iv_size())
      .SetTagSizeInBytes(16)
      .Build();
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesEaxParameters& parameters) {
  util::StatusOr<AesEaxParams> params = GetProtoParams(parameters);
  if (!params.ok()) return params.status();

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  AesEaxKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_key_size(parameters.GetKeySizeInBytes());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<AesEaxKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesEaxKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  SecretProto<google::crypto::tink::AesEaxKey> proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  if (!proto_key->ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesEaxKey proto");
  }
  if (proto_key->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesEaxParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  util::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(*variant)
          .SetKeySizeInBytes(proto_key->key_value().length())
          .SetIvSizeInBytes(proto_key->params().iv_size())
          // Legacy AES-EAX key proto format assumes 16-byte tags.
          .SetTagSizeInBytes(16)
          .Build();
  if (!parameters.ok()) return parameters.status();

  return AesEaxKey::Create(
      *parameters, RestrictedData(proto_key->key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesEaxKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<AesEaxParams> params = GetProtoParams(key.GetParameters());
  if (!params.ok()) return params.status();

  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  SecretProto<google::crypto::tink::AesEaxKey> proto_key;
  proto_key->set_version(0);
  proto_key->set_key_value(restricted_input->GetSecret(*token));
  *proto_key->mutable_params() = *params;

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();
  util::StatusOr<SecretData> serialized_proto =
      proto_key.SerializeAsSecretData();
  if (!serialized_proto.ok()) return serialized_proto.status();
  RestrictedData restricted_output =
      RestrictedData(SecretDataAsStringView(*serialized_proto), *token);
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      *output_prefix_type, key.GetIdRequirement());
}

AesEaxProtoParametersParserImpl* AesEaxProtoParametersParser() {
  static auto* parser =
      new AesEaxProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesEaxProtoParametersSerializerImpl* AesEaxProtoParametersSerializer() {
  static auto* serializer =
      new AesEaxProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesEaxProtoKeyParserImpl* AesEaxProtoKeyParser() {
  static auto* parser = new AesEaxProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesEaxProtoKeySerializerImpl* AesEaxProtoKeySerializer() {
  static auto* serializer = new AesEaxProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesEaxProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesEaxProtoParametersParser());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(AesEaxProtoParametersSerializer());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesEaxProtoKeyParser());
  if (!status.ok()) return status;

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesEaxProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
