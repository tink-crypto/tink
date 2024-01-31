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

#include "tink/signature/ecdsa_public_key.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::Status ValidatePublicPoint(EcdsaParameters::CurveType curve_type,
                                 const EcPoint& point) {
  subtle::EllipticCurveType curve;
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      curve = subtle::EllipticCurveType::NIST_P256;
      break;
    case EcdsaParameters::CurveType::kNistP384:
      curve = subtle::EllipticCurveType::NIST_P384;
      break;
    case EcdsaParameters::CurveType::kNistP521:
      curve = subtle::EllipticCurveType::NIST_P521;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown curve type: ", curve_type));
  }
  // Internally calls EC_POINT_set_affine_coordinates_GFp, which, in BoringSSL
  // and OpenSSL versions > 1.1.0, already checks if the point is on the curve.
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
    const EcdsaParameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case EcdsaParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case EcdsaParameters::Variant::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;
    case EcdsaParameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            "ID requirement must have value with kCrunchy or kLegacy");
      }
      return absl::StrCat(absl::HexStringToBytes("00"),
                          subtle::BigEndian32(*id_requirement));
    case EcdsaParameters::Variant::kTink:
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

util::Status ValidateIdRequirement(const EcdsaParameters& parameters,
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

util::StatusOr<EcdsaPublicKey> EcdsaPublicKey::Create(
    const EcdsaParameters& parameters, const EcPoint& public_point,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  util::Status id_requirement_validation =
      ValidateIdRequirement(parameters, id_requirement);
  if (!id_requirement_validation.ok()) {
    return id_requirement_validation;
  }

  util::Status public_key_validation =
      ValidatePublicPoint(parameters.GetCurveType(), public_point);
  if (!public_key_validation.ok()) {
    return public_key_validation;
  }

  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return EcdsaPublicKey(parameters, public_point, id_requirement,
                        *output_prefix);
}

bool EcdsaPublicKey::operator==(const Key& other) const {
  const EcdsaPublicKey* that = dynamic_cast<const EcdsaPublicKey*>(&other);
  if (that == nullptr) return false;
  return GetParameters() == that->GetParameters() &&
         id_requirement_ == that->id_requirement_ &&
         public_point_ == that->public_point_;
}

}  // namespace tink
}  // namespace crypto
