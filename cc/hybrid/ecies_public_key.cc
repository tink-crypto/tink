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

#include "tink/hybrid/ecies_public_key.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::Status ValidateNistCurvePublicKey(EciesParameters::CurveType curve_type,
                                        const EcPoint& point) {
  subtle::EllipticCurveType curve;
  switch (curve_type) {
    case EciesParameters::CurveType::kNistP256:
      curve = subtle::EllipticCurveType::NIST_P256;
      break;
    case EciesParameters::CurveType::kNistP384:
      curve = subtle::EllipticCurveType::NIST_P384;
      break;
    case EciesParameters::CurveType::kNistP521:
      curve = subtle::EllipticCurveType::NIST_P521;
      break;
    case EciesParameters::CurveType::kX25519:
      curve = subtle::EllipticCurveType::CURVE25519;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown curve type: ", curve_type));
  }
  util::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(curve, point.GetX().GetValue(),
                           point.GetY().GetValue());
  if (!ec_point.ok()) {
    return ec_point.status();
  }
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  if (EC_POINT_is_on_curve(group->get(), ec_point->get(), /*ctx=*/nullptr) !=
      1) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EC public point is not on curve ",
                                     subtle::EnumToString(curve)));
  }
  return util::OkStatus();
}

util::StatusOr<std::string> ComputeOutputPrefix(
    const EciesParameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case EciesParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case EciesParameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kCrunchy");
      }
      return absl::StrCat(absl::HexStringToBytes("00"),
                          subtle::BigEndian32(*id_requirement));
    case EciesParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kTink");
      }
      return absl::StrCat(absl::HexStringToBytes("01"),
                          subtle::BigEndian32(*id_requirement));
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

util::Status ValidateIdRequirement(const EciesParameters& parameters,
                                   absl::optional<int> id_requirement) {
  if (parameters.HasIdRequirement() && !id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters.HasIdRequirement() && id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  return util::OkStatus();
}

}  // namespace

util::StatusOr<EciesPublicKey> EciesPublicKey::CreateForNistCurve(
    const EciesParameters& parameters, const EcPoint& point,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  util::Status id_requirement_validation =
      ValidateIdRequirement(parameters, id_requirement);
  if (!id_requirement_validation.ok()) {
    return id_requirement_validation;
  }

  util::Status public_key_validation =
      ValidateNistCurvePublicKey(parameters.GetCurveType(), point);
  if (!public_key_validation.ok()) {
    return public_key_validation;
  }

  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return EciesPublicKey(parameters, point, id_requirement, *output_prefix);
}

util::StatusOr<EciesPublicKey> EciesPublicKey::CreateForCurveX25519(
    const EciesParameters& parameters, absl::string_view public_key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  util::Status id_requirement_validation =
      ValidateIdRequirement(parameters, id_requirement);
  if (!id_requirement_validation.ok()) {
    return id_requirement_validation;
  }

  // Validate key length.
  if (public_key_bytes.length() != internal::X25519KeyPubKeySize()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Invalid X25519 public key length (expected %d, got %d)",
            internal::X25519KeyPubKeySize(), public_key_bytes.length()));
  }

  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return EciesPublicKey(parameters, public_key_bytes, id_requirement,
                        *output_prefix);
}

bool EciesPublicKey::operator==(const Key& other) const {
  const EciesPublicKey* that = dynamic_cast<const EciesPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  if (point_ != that->point_) {
    return false;
  }
  return public_key_bytes_ == that->public_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
