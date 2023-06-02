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

#include "tink/mac/hmac_proto_serialization.h"

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
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::HmacParams;
using ::google::crypto::tink::OutputPrefixType;

using HmacProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   HmacParameters>;
using HmacProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<HmacParameters,
                                       internal::ProtoParametersSerialization>;
using HmacProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, HmacKey>;
using HmacProtoKeySerializerImpl =
    internal::KeySerializerImpl<HmacKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacKey";

util::StatusOr<HmacParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::CRUNCHY:
      return HmacParameters::Variant::kCrunchy;
    case OutputPrefixType::LEGACY:
      return HmacParameters::Variant::kLegacy;
    case OutputPrefixType::RAW:
      return HmacParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return HmacParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HmacParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    HmacParameters::Variant variant) {
  switch (variant) {
    case HmacParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case HmacParameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case HmacParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case HmacParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<HmacParameters::HashType> ToHashType(HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return HmacParameters::HashType::kSha1;
    case HashType::SHA224:
      return HmacParameters::HashType::kSha224;
    case HashType::SHA256:
      return HmacParameters::HashType::kSha256;
    case HashType::SHA384:
      return HmacParameters::HashType::kSha384;
    case HashType::SHA512:
      return HmacParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(HmacParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacParameters::HashType::kSha1:
      return HashType::SHA1;
    case HmacParameters::HashType::kSha224:
      return HashType::SHA224;
    case HmacParameters::HashType::kSha256:
      return HashType::SHA256;
    case HmacParameters::HashType::kSha384:
      return HashType::SHA384;
    case HmacParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HmacParameters::HashType");
  }
}

util::StatusOr<HmacParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HmacParameters.");
  }

  HmacKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HmacKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing HmacParameters failed: only version 0 is accepted");
  }

  util::StatusOr<HmacParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  util::StatusOr<HmacParameters::HashType> hash_type =
      ToHashType(proto_key_format.params().hash());
  if (!hash_type.ok()) return variant.status();

  return HmacParameters::Create(proto_key_format.key_size(),
                                proto_key_format.params().tag_size(),
                                *hash_type, *variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const HmacParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();
  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) return proto_hash_type.status();

  HmacParams proto_params;
  proto_params.set_tag_size(parameters.CryptographicTagSizeInBytes());
  proto_params.set_hash(*proto_hash_type);
  HmacKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_version(0);
  *proto_key_format.mutable_params() = proto_params;

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<HmacKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HmacKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  google::crypto::tink::HmacKey proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  // OSS proto library complains if input is not converted to a string.
  if (!proto_key.ParseFromString(
          std::string(restricted_data.GetSecret(*token)))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HmacKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HmacParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();
  util::StatusOr<HmacParameters::HashType> hash_type =
      ToHashType(proto_key.params().hash());
  if (!hash_type.ok()) return variant.status();

  util::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      proto_key.key_value().length(), proto_key.params().tag_size(), *hash_type,
      *variant);
  if (!parameters.ok()) return parameters.status();

  return HmacKey::Create(*parameters,
                         RestrictedData(proto_key.key_value(), *token),
                         serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const HmacKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  if (!restricted_input.ok()) return restricted_input.status();
  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!proto_hash_type.ok()) return proto_hash_type.status();

  HmacParams proto_params;
  proto_params.set_tag_size(key.GetParameters().CryptographicTagSizeInBytes());
  proto_params.set_hash(*proto_hash_type);
  google::crypto::tink::HmacKey proto_key;
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

HmacProtoParametersParserImpl* HmacProtoParametersParser() {
  static auto* parser =
      new HmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

HmacProtoParametersSerializerImpl* HmacProtoParametersSerializer() {
  static auto* serializer =
      new HmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

HmacProtoKeyParserImpl* HmacProtoKeyParser() {
  static auto* parser = new HmacProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

HmacProtoKeySerializerImpl* HmacProtoKeySerializer() {
  static auto* serializer = new HmacProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterHmacProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(HmacProtoParametersParser());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(HmacProtoParametersSerializer());
  if (!status.ok()) return status;

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(HmacProtoKeyParser());
  if (!status.ok()) return status;

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(HmacProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
