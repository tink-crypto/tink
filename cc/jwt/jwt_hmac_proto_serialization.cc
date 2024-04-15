// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_hmac_proto_serialization.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::JwtHmacAlgorithm;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using JwtHmacProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtHmacParameters>;
using JwtHmacProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtHmacParameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtHmacKey";

util::StatusOr<JwtHmacParameters::KidStrategy> ToKidStrategy(
    OutputPrefixType output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      if (has_custom_kid) {
        return JwtHmacParameters::KidStrategy::kCustom;
      }
      return JwtHmacParameters::KidStrategy::kIgnored;
    case OutputPrefixType::TINK:
      return JwtHmacParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid OutputPrefixType for JwtHmacKeyFormat.");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    JwtHmacParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtHmacParameters::KidStrategy::kCustom:
      return OutputPrefixType::RAW;
    case JwtHmacParameters::KidStrategy::kIgnored:
      return OutputPrefixType::RAW;
    case JwtHmacParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixType::TINK;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtHmacParameters::KidStrategy.");
  }
}

util::StatusOr<JwtHmacParameters::Algorithm> FromProtoAlgorithm(
    JwtHmacAlgorithm algorithm) {
  switch (algorithm) {
    case JwtHmacAlgorithm::HS256:
      return JwtHmacParameters::Algorithm::kHs256;
    case JwtHmacAlgorithm::HS384:
      return JwtHmacParameters::Algorithm::kHs384;
    case JwtHmacAlgorithm::HS512:
      return JwtHmacParameters::Algorithm::kHs512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtHmacAlgorithm.");
  }
}

util::StatusOr<JwtHmacAlgorithm> ToProtoAlgorithm(
    JwtHmacParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtHmacParameters::Algorithm::kHs256:
      return JwtHmacAlgorithm::HS256;
    case JwtHmacParameters::Algorithm::kHs384:
      return JwtHmacAlgorithm::HS384;
    case JwtHmacParameters::Algorithm::kHs512:
      return JwtHmacAlgorithm::HS512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtHmacParameters::Algorithm");
  }
}

util::StatusOr<JwtHmacParameters> ToParameters(
    int key_size_in_bytes, OutputPrefixType output_prefix_type,
    JwtHmacAlgorithm proto_algorithm, bool has_custom_kid) {
  util::StatusOr<JwtHmacParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }
  util::StatusOr<JwtHmacParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }
  return JwtHmacParameters::Create(key_size_in_bytes, *kid_strategy,
                                   *algorithm);
}

util::StatusOr<JwtHmacParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtHmacParameters.");
  }
  JwtHmacKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtHmacKeyFormat proto.");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtHmacParameters failed: only version 0 is accepted.");
  }

  return ToParameters(proto_key_format.key_size(),
                      serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.algorithm(), /*has_custom_kid=*/false);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const JwtHmacParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtHmacParameters::KidStrategy::kCustom) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Unable to serialize JwtHmacParameters::KidStrategy::kCustom.");
  }
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  util::StatusOr<JwtHmacAlgorithm> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(parameters.KeySizeInBytes());
  format.set_algorithm(*proto_algorithm);

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, format.SerializeAsString());
}

JwtHmacProtoParametersParserImpl* JwtHmacProtoParametersParser() {
  static auto* parser =
      new JwtHmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

JwtHmacProtoParametersSerializerImpl* JwtHmacProtoParametersSerializer() {
  static auto* serializer =
      new JwtHmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

}  // namespace

util::Status RegisterJwtHmacProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(JwtHmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(JwtHmacProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
