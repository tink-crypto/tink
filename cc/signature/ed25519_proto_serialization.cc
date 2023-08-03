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

#include "tink/signature/ed25519_proto_serialization.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::Ed25519KeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using Ed25519ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   Ed25519Parameters>;
using Ed25519ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<Ed25519Parameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

util::StatusOr<Ed25519Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return Ed25519Parameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return Ed25519Parameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return Ed25519Parameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return Ed25519Parameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine Ed25519Parameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    Ed25519Parameters::Variant variant) {
  switch (variant) {
    case Ed25519Parameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case Ed25519Parameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case Ed25519Parameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case Ed25519Parameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<Ed25519Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing Ed25519Parameters.");
  }

  Ed25519KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse Ed25519KeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<Ed25519Parameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  return Ed25519Parameters::Create(*variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const Ed25519Parameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  Ed25519KeyFormat proto_key_format;
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

Ed25519ProtoParametersParserImpl* Ed25519ProtoParametersParser() {
  static auto* parser =
      new Ed25519ProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

Ed25519ProtoParametersSerializerImpl* Ed25519ProtoParametersSerializer() {
  static auto* serializer = new Ed25519ProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

}  // namespace

util::Status RegisterEd25519ProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(Ed25519ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(Ed25519ProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
