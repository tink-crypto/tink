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

#include "tink/signature/ecdsa_parameters.h"

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

EcdsaParameters::Builder& EcdsaParameters::Builder::SetCurveType(
    CurveType curve_type) {
  curve_type_ = curve_type;
  return *this;
}

EcdsaParameters::Builder& EcdsaParameters::Builder::SetHashType(
    HashType hash_type) {
  hash_type_ = hash_type;
  return *this;
}

EcdsaParameters::Builder& EcdsaParameters::Builder::SetSignatureEncoding(
    SignatureEncoding signature_encoding) {
  signature_encoding_ = signature_encoding;
  return *this;
}

EcdsaParameters::Builder& EcdsaParameters::Builder::SetVariant(
    Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<EcdsaParameters> EcdsaParameters::Builder::Build() {
  if (!curve_type_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "CurveType is not set.");
  }

  if (!hash_type_.has_value()) {
    return absl::InvalidArgumentError("HashType is not set.");
  }

  if (!signature_encoding_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SignatureEncoding is not set.");
  }

  if (!variant_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Variant is not set.");
  }

  // Validate CurveType.
  static constexpr CurveType kSupportedCurves[] = {
      CurveType::kNistP256, CurveType::kNistP384, CurveType::kNistP521};
  if (!absl::c_linear_search(kSupportedCurves, *curve_type_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create Ecdsa parameters with unknown CurveType.");
  }

  // Validate HashType.
  static constexpr HashType kSupportedHashes[] = {
      HashType::kSha256, HashType::kSha384, HashType::kSha512};
  if (!absl::c_linear_search(kSupportedHashes, *hash_type_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create Ecdsa parameters with unknown HashType.");
  }

  // Check requirements for the curve and the hash types.
  switch (*curve_type_) {
    case CurveType::kNistP256:
      if (*hash_type_ != HashType::kSha256) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "NIST_P256 curve requires SHA256.");
      }
      break;
    case CurveType::kNistP384:
      if (*hash_type_ != HashType::kSha384 &&
          *hash_type_ != HashType::kSha512) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "NIST_P384 curve requires SHA384 or SHA512.");
      }
      break;
    case CurveType::kNistP521:
      if (*hash_type_ != HashType::kSha512) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "NIST_P521 curve requires SHA512.");
      }
      break;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Cannot create Ecdsa parameters with unknown CurveType.");
  }

  // Validate SignatureEncoding.
  static constexpr SignatureEncoding kSupportedEncodings[] = {
      SignatureEncoding::kDer, SignatureEncoding::kIeeeP1363};
  if (!absl::c_linear_search(kSupportedEncodings, *signature_encoding_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create Ecdsa parameters with unknown SignatureEncoding.");
  }

  // Validate variant.
  static constexpr Variant kSupportedVariants[] = {
      Variant::kTink, Variant::kCrunchy, Variant::kLegacy, Variant::kNoPrefix};
  if (!absl::c_linear_search(kSupportedVariants, *variant_)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create Ecdsa parameters with unknown Variant.");
  }

  return EcdsaParameters(*curve_type_, *hash_type_, *signature_encoding_,
                         *variant_);
}

bool EcdsaParameters::operator==(const Parameters& other) const {
  const EcdsaParameters* that = dynamic_cast<const EcdsaParameters*>(&other);
  if (that == nullptr) return false;
  return curve_type_ == that->curve_type_ && hash_type_ == that->hash_type_ &&
         signature_encoding_ == that->signature_encoding_ &&
         variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
