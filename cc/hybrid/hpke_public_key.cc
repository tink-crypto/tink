// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_public_key.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::Status ValidatePublicKey(HpkeParameters::KemId kem_id,
                               absl::string_view public_key_bytes) {
  int expected_length;
  subtle::EllipticCurveType curve;
  switch (kem_id) {
      // Key lengths from 'Npk' column in
      // https://www.rfc-editor.org/rfc/rfc9180.html#table-2.
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      curve = subtle::EllipticCurveType::NIST_P256;
      expected_length = 65;
      break;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      curve = subtle::EllipticCurveType::NIST_P384;
      expected_length = 97;
      break;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      curve = subtle::EllipticCurveType::NIST_P521;
      expected_length = 133;
      break;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      curve = subtle::EllipticCurveType::CURVE25519;
      expected_length = 32;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown KEM ID: ", kem_id));
  }

  // Validate key length.
  if (expected_length != public_key_bytes.length()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Invalid public key length for KEM %d (expected %d, got %d)",
            kem_id, expected_length, public_key_bytes.length()));
  }

  // Validate that NIST curve public point is actually on the specified curve.
  //
  // NOTE: `EcPointDecode()` verifies that the point is on the curve via
  // `SslGetEcPointFromEncoded()` for the uncompressed point format.
  if (curve != subtle::EllipticCurveType::CURVE25519) {
    util::Status decode_status =
        internal::EcPointDecode(curve, subtle::EcPointFormat::UNCOMPRESSED,
                                public_key_bytes)
            .status();
    if (!decode_status.ok()) {
      return decode_status;
    }
  }

  return util::OkStatus();
}

util::StatusOr<std::string> ComputeOutputPrefix(
    const HpkeParameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case HpkeParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case HpkeParameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kCrunchy");
      }
      return absl::StrCat(absl::HexStringToBytes("00"),
                          subtle::BigEndian32(*id_requirement));
    case HpkeParameters::Variant::kTink:
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

}  // namespace

util::StatusOr<HpkePublicKey> HpkePublicKey::Create(
    const HpkeParameters& parameters, absl::string_view public_key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
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

  util::Status validation =
      ValidatePublicKey(parameters.GetKemId(), public_key_bytes);
  if (!validation.ok()) {
    return validation;
  }

  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return HpkePublicKey(parameters, public_key_bytes, id_requirement,
                       *output_prefix);
}

bool HpkePublicKey::operator==(const Key& other) const {
  const HpkePublicKey* that = dynamic_cast<const HpkePublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return public_key_bytes_ == that->public_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
