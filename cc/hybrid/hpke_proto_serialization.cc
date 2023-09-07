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

#include "tink/hybrid/hpke_proto_serialization.h"

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::OutputPrefixType;

using HpkeProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   HpkeParameters>;
using HpkeProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<HpkeParameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

util::StatusOr<HpkeParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return HpkeParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return HpkeParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return HpkeParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HpkeParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    HpkeParameters::Variant variant) {
  switch (variant) {
    case HpkeParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case HpkeParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case HpkeParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type.");
  }
}

util::StatusOr<HpkeParameters::KemId> ToKemId(HpkeKem kem) {
  switch (kem) {
    case HpkeKem::DHKEM_P256_HKDF_SHA256:
      return HpkeParameters::KemId::kDhkemP256HkdfSha256;
    case HpkeKem::DHKEM_P384_HKDF_SHA384:
      return HpkeParameters::KemId::kDhkemP384HkdfSha384;
    case HpkeKem::DHKEM_P521_HKDF_SHA512:
      return HpkeParameters::KemId::kDhkemP521HkdfSha512;
    case HpkeKem::DHKEM_X25519_HKDF_SHA256:
      return HpkeParameters::KemId::kDhkemX25519HkdfSha256;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KEM.");
  }
}

util::StatusOr<HpkeKem> FromKemId(HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return HpkeKem::DHKEM_P256_HKDF_SHA256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return HpkeKem::DHKEM_P384_HKDF_SHA384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return HpkeKem::DHKEM_P521_HKDF_SHA512;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return HpkeKem::DHKEM_X25519_HKDF_SHA256;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KEM.");
  }
}

util::StatusOr<HpkeParameters::KdfId> ToKdfId(HpkeKdf kdf) {
  switch (kdf) {
    case HpkeKdf::HKDF_SHA256:
      return HpkeParameters::KdfId::kHkdfSha256;
    case HpkeKdf::HKDF_SHA384:
      return HpkeParameters::KdfId::kHkdfSha384;
    case HpkeKdf::HKDF_SHA512:
      return HpkeParameters::KdfId::kHkdfSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KDF.");
  }
}

util::StatusOr<HpkeKdf> FromKdfId(HpkeParameters::KdfId kdf_id) {
  switch (kdf_id) {
    case HpkeParameters::KdfId::kHkdfSha256:
      return HpkeKdf::HKDF_SHA256;
    case HpkeParameters::KdfId::kHkdfSha384:
      return HpkeKdf::HKDF_SHA384;
    case HpkeParameters::KdfId::kHkdfSha512:
      return HpkeKdf::HKDF_SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KDF.");
  }
}

util::StatusOr<HpkeParameters::AeadId> ToAeadId(HpkeAead aead) {
  switch (aead) {
    case HpkeAead::AES_128_GCM:
      return HpkeParameters::AeadId::kAesGcm128;
    case HpkeAead::AES_256_GCM:
      return HpkeParameters::AeadId::kAesGcm256;
    case HpkeAead::CHACHA20_POLY1305:
      return HpkeParameters::AeadId::kChaChaPoly1305;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AEAD.");
  }
}

util::StatusOr<HpkeAead> FromAeadId(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
      return HpkeAead::AES_128_GCM;
    case HpkeParameters::AeadId::kAesGcm256:
      return HpkeAead::AES_256_GCM;
    case HpkeParameters::AeadId::kChaChaPoly1305:
      return HpkeAead::CHACHA20_POLY1305;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AEAD.");
  }
}

util::StatusOr<HpkeParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HpkeParameters.");
  }

  HpkeKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HpkeKeyFormat proto");
  }
  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HpkeKeyFormat proto is missing params field.");
  }

  util::StatusOr<HpkeParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<HpkeParameters::KemId> kem_id =
      ToKemId(proto_key_format.params().kem());
  if (!kem_id.ok()) {
    return kem_id.status();
  }

  util::StatusOr<HpkeParameters::KdfId> kdf_id =
      ToKdfId(proto_key_format.params().kdf());
  if (!kdf_id.ok()) {
    return kdf_id.status();
  }

  util::StatusOr<HpkeParameters::AeadId> aead_id =
      ToAeadId(proto_key_format.params().aead());
  if (!aead_id.ok()) {
    return aead_id.status();
  }

  return HpkeParameters::Builder()
      .SetVariant(*variant)
      .SetKemId(*kem_id)
      .SetKdfId(*kdf_id)
      .SetAeadId(*aead_id)
      .Build();
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const HpkeParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<HpkeKem> kem = FromKemId(parameters.GetKemId());
  if (!kem.ok()) {
    return kem.status();
  }

  util::StatusOr<HpkeKdf> kdf = FromKdfId(parameters.GetKdfId());
  if (!kdf.ok()) {
    return kdf.status();
  }

  util::StatusOr<HpkeAead> aead = FromAeadId(parameters.GetAeadId());
  if (!aead.ok()) {
    return aead.status();
  }

  HpkeParams params;
  params.set_kem(*kem);
  params.set_kdf(*kdf);
  params.set_aead(*aead);
  HpkeKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = params;

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

HpkeProtoParametersParserImpl* HpkeProtoParametersParser() {
  static auto* parser =
      new HpkeProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

HpkeProtoParametersSerializerImpl* HpkeProtoParametersSerializer() {
  static auto* serializer = new HpkeProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

}  // namespace

util::Status RegisterHpkeProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(HpkeProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(HpkeProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
