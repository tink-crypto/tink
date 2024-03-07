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

#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
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
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::AesCtrKeyFormat;
using ::google::crypto::tink::AesCtrParams;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::HmacParams;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

using AesCtrHmacAeadProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCtrHmacAeadParameters>;
using AesCtrHmacAeadProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCtrHmacAeadParameters,
                                       internal::ProtoParametersSerialization>;
using AesCtrHmacAeadProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesCtrHmacAeadKey>;
using AesCtrHmacAeadProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesCtrHmacAeadKey,
                                internal::ProtoKeySerialization>;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

util::StatusOr<AesCtrHmacAeadParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return AesCtrHmacAeadParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return AesCtrHmacAeadParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesCtrHmacAeadParameters::Variant::kTink;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine AesCtrHmacAeadParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesCtrHmacAeadParameters::Variant variant) {
  switch (variant) {
    case AesCtrHmacAeadParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesCtrHmacAeadParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesCtrHmacAeadParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<AesCtrHmacAeadParameters::HashType> ToHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return AesCtrHmacAeadParameters::HashType::kSha1;
    case HashType::SHA224:
      return AesCtrHmacAeadParameters::HashType::kSha224;
    case HashType::SHA256:
      return AesCtrHmacAeadParameters::HashType::kSha256;
    case HashType::SHA384:
      return AesCtrHmacAeadParameters::HashType::kSha384;
    case HashType::SHA512:
      return AesCtrHmacAeadParameters::HashType::kSha512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine AesCtrHmacAeadParameters::HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    AesCtrHmacAeadParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacAeadParameters::HashType::kSha1:
      return HashType::SHA1;
    case AesCtrHmacAeadParameters::HashType::kSha224:
      return HashType::SHA224;
    case AesCtrHmacAeadParameters::HashType::kSha256:
      return HashType::SHA256;
    case AesCtrHmacAeadParameters::HashType::kSha384:
      return HashType::SHA384;
    case AesCtrHmacAeadParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HmacParams> GetHmacProtoParams(
    const AesCtrHmacAeadParameters& parameters) {
  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) return proto_hash_type.status();

  HmacParams hmac_params;
  hmac_params.set_tag_size(parameters.GetTagSizeInBytes());
  hmac_params.set_hash(*proto_hash_type);

  return hmac_params;
}

util::StatusOr<AesCtrHmacAeadParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Wrong type URL when parsing AesCtrHmacAeadParameters: ",
                     serialization.GetKeyTemplate().type_url()));
  }

  AesCtrHmacAeadKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCtrHmacAeadKeyFormat proto");
  }

  if (proto_key_format.hmac_key_format().version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse hmac key format: only version 0 "
                        "is accepted.");
  }

  util::StatusOr<AesCtrHmacAeadParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<AesCtrHmacAeadParameters::HashType> hash_type =
      ToHashType(proto_key_format.hmac_key_format().params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return AesCtrHmacAeadParameters::Builder()
      .SetAesKeySizeInBytes(proto_key_format.aes_ctr_key_format().key_size())
      .SetHmacKeySizeInBytes(proto_key_format.hmac_key_format().key_size())
      .SetIvSizeInBytes(
          proto_key_format.aes_ctr_key_format().params().iv_size())
      .SetTagSizeInBytes(proto_key_format.hmac_key_format().params().tag_size())
      .SetHashType(*hash_type)
      .SetVariant(*variant)
      .Build();
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesCtrHmacAeadParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format;
  HmacKeyFormat& hmac_key_format =
      *aes_ctr_hmac_aead_key_format.mutable_hmac_key_format();
  AesCtrKeyFormat& aes_ctr_key_format =
      *aes_ctr_hmac_aead_key_format.mutable_aes_ctr_key_format();

  util::StatusOr<HmacParams> hmac_params = GetHmacProtoParams(parameters);
  if (!hmac_params.ok()) {
    return hmac_params.status();
  }

  *hmac_key_format.mutable_params() = *hmac_params;
  hmac_key_format.set_key_size(parameters.GetHmacKeySizeInBytes());

  AesCtrParams& aes_ctr_params = *aes_ctr_key_format.mutable_params();
  aes_ctr_params.set_iv_size(parameters.GetIvSizeInBytes());
  aes_ctr_key_format.set_key_size(parameters.GetAesKeySizeInBytes());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type,
      aes_ctr_hmac_aead_key_format.SerializeAsString());
}

util::StatusOr<AesCtrHmacAeadKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCtrHmacAeadKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  SecretProto<google::crypto::tink::AesCtrHmacAeadKey> proto_key;
  RestrictedData restricted_data = serialization.SerializedKeyProto();
  if (!proto_key->ParseFromString(restricted_data.GetSecret(*token))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCtrHmacAeadKey proto");
  }
  if (proto_key->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (proto_key->aes_ctr_key().version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys inner AES CTR keys are accepted.");
  }
  if (proto_key->hmac_key().version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys inner HMAC keys are accepted.");
  }

  util::StatusOr<AesCtrHmacAeadParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<AesCtrHmacAeadParameters::HashType> hash_type =
      ToHashType(proto_key->hmac_key().params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(proto_key->aes_ctr_key().key_value().size())
          .SetHmacKeySizeInBytes(proto_key->hmac_key().key_value().size())
          .SetIvSizeInBytes(proto_key->aes_ctr_key().params().iv_size())
          .SetTagSizeInBytes(proto_key->hmac_key().params().tag_size())
          .SetHashType(*hash_type)
          .SetVariant(*variant)
          .Build();
  if (!parameters.ok()) return parameters.status();

  return AesCtrHmacAeadKey::Builder()
      .SetParameters(*parameters)
      .SetAesKeyBytes(
          RestrictedData(proto_key->aes_ctr_key().key_value(), *token))
      .SetHmacKeyBytes(
          RestrictedData(proto_key->hmac_key().key_value(), *token))
      .SetIdRequirement(serialization.IdRequirement())
      .Build(GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesCtrHmacAeadKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<RestrictedData> restricted_aes_input =
      key.GetAesKeyBytes(GetPartialKeyAccess());
  if (!restricted_aes_input.ok()) {
    return restricted_aes_input.status();
  }

  util::StatusOr<RestrictedData> restricted_hmac_input =
      key.GetHmacKeyBytes(GetPartialKeyAccess());
  if (!restricted_hmac_input.ok()) {
    return restricted_hmac_input.status();
  }

  SecretProto<google::crypto::tink::AesCtrKey> aes_ctr_proto_key;
  aes_ctr_proto_key->set_version(0);
  aes_ctr_proto_key->set_key_value(restricted_aes_input->GetSecret(*token));
  aes_ctr_proto_key->mutable_params()->set_iv_size(
      key.GetParameters().GetIvSizeInBytes());

  util::StatusOr<HmacParams> hmac_params =
      GetHmacProtoParams(key.GetParameters());
  if (!hmac_params.ok()) {
    return hmac_params.status();
  }

  SecretProto<google::crypto::tink::HmacKey> hmac_proto_key;
  hmac_proto_key->set_version(0);
  hmac_proto_key->set_key_value(restricted_hmac_input->GetSecret(*token));
  *hmac_proto_key->mutable_params() = *hmac_params;

  SecretProto<google::crypto::tink::AesCtrHmacAeadKey>
      aes_ctr_hmac_aead_proto_key;
  aes_ctr_hmac_aead_proto_key->set_version(0);
  *aes_ctr_hmac_aead_proto_key->mutable_aes_ctr_key() = *aes_ctr_proto_key;
  *aes_ctr_hmac_aead_proto_key->mutable_hmac_key() = *hmac_proto_key;

  util::StatusOr<SecretData> serialized_proto =
      aes_ctr_hmac_aead_proto_key.SerializeAsSecretData();
  if (!serialized_proto.ok()) return serialized_proto.status();
  RestrictedData restricted_output =
      RestrictedData(SecretDataAsStringView(*serialized_proto), *token);

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyData::SYMMETRIC, *output_prefix_type,
      key.GetIdRequirement());
}

AesCtrHmacAeadProtoParametersParserImpl& AesCtrHmacAeadProtoParametersParser() {
  static auto* parser =
      new AesCtrHmacAeadProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

AesCtrHmacAeadProtoParametersSerializerImpl&
AesCtrHmacAeadProtoParametersSerializer() {
  static auto* serializer = new AesCtrHmacAeadProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return *serializer;
}

AesCtrHmacAeadProtoKeyParserImpl& AesCtrHmacAeadProtoKeyParser() {
  static auto* parser =
      new AesCtrHmacAeadProtoKeyParserImpl(kTypeUrl, ParseKey);
  return *parser;
}

AesCtrHmacAeadProtoKeySerializerImpl& AesCtrHmacAeadProtoKeySerializer() {
  static auto* serializer =
      new AesCtrHmacAeadProtoKeySerializerImpl(SerializeKey);
  return *serializer;
}

}  // namespace

util::Status RegisterAesCtrHmacAeadProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&AesCtrHmacAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(
                   &AesCtrHmacAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&AesCtrHmacAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&AesCtrHmacAeadProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
