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

#include "tink/aead/xchacha20_poly1305_proto_serialization.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
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
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;

using XChaCha20Poly1305ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   XChaCha20Poly1305Parameters>;
using XChaCha20Poly1305ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<XChaCha20Poly1305Parameters,
                                       internal::ProtoParametersSerialization>;
using XChaCha20Poly1305ProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            XChaCha20Poly1305Key>;
using XChaCha20Poly1305ProtoKeySerializerImpl =
    internal::KeySerializerImpl<XChaCha20Poly1305Key,
                                internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

util::StatusOr<XChaCha20Poly1305Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return XChaCha20Poly1305Parameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return XChaCha20Poly1305Parameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return XChaCha20Poly1305Parameters::Variant::kTink;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine XChaCha20Poly1305Parameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    XChaCha20Poly1305Parameters::Variant variant) {
  switch (variant) {
    case XChaCha20Poly1305Parameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case XChaCha20Poly1305Parameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case XChaCha20Poly1305Parameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<XChaCha20Poly1305Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing XChaCha20Poly1305Parameters.");
  }

  XChaCha20Poly1305KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse XChaCha20Poly1305KeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<XChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  return XChaCha20Poly1305Parameters::Create(*variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const XChaCha20Poly1305Parameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  XChaCha20Poly1305KeyFormat proto_key_format;
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<XChaCha20Poly1305Key> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing XChaCha20Poly1305Key.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  google::crypto::tink::XChaCha20Poly1305Key proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse XChaCha20Poly1305Key proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<XChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  util::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(*variant);
  if (!parameters.ok()) return parameters.status();

  return XChaCha20Poly1305Key::Create(
      parameters->GetVariant(), RestrictedData(proto_key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const XChaCha20Poly1305Key& key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  google::crypto::tink::XChaCha20Poly1305Key proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->GetSecret(*token));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  RestrictedData restricted_output =
      RestrictedData(proto_key.SerializeAsString(), *token);
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      *output_prefix_type, key.GetIdRequirement());
}

XChaCha20Poly1305ProtoParametersParserImpl*
XChaCha20Poly1305ProtoParametersParser() {
  static auto* parser =
      new XChaCha20Poly1305ProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

XChaCha20Poly1305ProtoParametersSerializerImpl*
XChaCha20Poly1305ProtoParametersSerializer() {
  static auto* serializer = new XChaCha20Poly1305ProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

XChaCha20Poly1305ProtoKeyParserImpl* XChaCha20Poly1305ProtoKeyParser() {
  static auto* parser =
      new XChaCha20Poly1305ProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

XChaCha20Poly1305ProtoKeySerializerImpl* XChaCha20Poly1305ProtoKeySerializer() {
  static auto* serializer =
      new XChaCha20Poly1305ProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterXChaCha20Poly1305ProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(XChaCha20Poly1305ProtoParametersParser());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(
                   XChaCha20Poly1305ProtoParametersSerializer());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(XChaCha20Poly1305ProtoKeyParser());
  if (!status.ok()) return status;

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(XChaCha20Poly1305ProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
