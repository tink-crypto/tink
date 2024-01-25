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

#include "tink/hybrid/ecies_parameters.h"

#include <memory>
#include <set>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

bool IsNistCurve(EciesParameters::CurveType curve_type) {
  return curve_type == EciesParameters::CurveType::kNistP256 ||
         curve_type == EciesParameters::CurveType::kNistP384 ||
         curve_type == EciesParameters::CurveType::kNistP521;
}

}  // namespace

EciesParameters::Builder& EciesParameters::Builder::SetCurveType(
    CurveType curve_type) {
  curve_type_ = curve_type;
  return *this;
}

EciesParameters::Builder& EciesParameters::Builder::SetHashType(
    HashType hash_type) {
  hash_type_ = hash_type;
  return *this;
}

EciesParameters::Builder& EciesParameters::Builder::SetNistCurvePointFormat(
    PointFormat point_format) {
  point_format_ = point_format;
  return *this;
}

EciesParameters::Builder& EciesParameters::Builder::SetDemId(DemId dem_id) {
  dem_id_ = dem_id;
  return *this;
}

EciesParameters::Builder& EciesParameters::Builder::SetSalt(
    absl::string_view salt) {
  if (!salt.empty()) {
    salt_ = std::string(salt);
  }
  return *this;
}

EciesParameters::Builder& EciesParameters::Builder::SetVariant(
    Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<EciesParameters> EciesParameters::Builder::Build() {
  static const std::set<CurveType>* kSupportedCurves =
      new std::set<CurveType>({CurveType::kNistP256, CurveType::kNistP384,
                               CurveType::kNistP521, CurveType::kX25519});
  if (kSupportedCurves->find(curve_type_) == kSupportedCurves->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create ECIES parameters with unknown curve type.");
  }

  static const std::set<HashType>* kSupportedHashes = new std::set<HashType>(
      {HashType::kSha1, HashType::kSha224, HashType::kSha256, HashType::kSha384,
       HashType::kSha512});
  if (kSupportedHashes->find(hash_type_) == kSupportedHashes->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create ECIES parameters with unknown hash type.");
  }

  static const std::set<absl::optional<PointFormat>>* kSupportedPointFormats =
      new std::set<absl::optional<PointFormat>>(
          {PointFormat::kCompressed, PointFormat::kUncompressed,
           PointFormat::kLegacyUncompressed, absl::nullopt});
  if (kSupportedPointFormats->find(point_format_) ==
      kSupportedPointFormats->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create ECIES parameters with unknown point format.");
  }

  static const std::set<DemId>* kSupportedDemIds = new std::set<DemId>(
      {DemId::kAes128GcmRaw, DemId::kAes256GcmRaw, DemId::kAes256SivRaw});
  if (kSupportedDemIds->find(dem_id_) == kSupportedDemIds->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create ECIES parameters with unknown DEM.");
  }

  static const std::set<Variant>* kSupportedVariants = new std::set<Variant>(
      {Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix});
  if (kSupportedVariants->find(variant_) == kSupportedVariants->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create ECIES parameters with unknown variant.");
  }

  if (curve_type_ == EciesParameters::CurveType::kX25519 &&
      point_format_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Point format must not be specified for the X25519 curve.");
  }

  if (IsNistCurve(curve_type_) && !point_format_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Point format must be specified for a NIST curve.");
  }

  return EciesParameters(curve_type_, hash_type_, point_format_, dem_id_, salt_,
                         variant_);
}

util::StatusOr<std::unique_ptr<Parameters>>
EciesParameters::CreateDemParameters() const {
  switch (dem_id_) {
    case DemId::kAes128GcmRaw: {
      util::StatusOr<AesGcmParameters> aes_128_gcm_raw =
          AesGcmParameters::Builder()
              .SetKeySizeInBytes(16)
              .SetIvSizeInBytes(12)
              .SetTagSizeInBytes(16)
              .SetVariant(AesGcmParameters::Variant::kNoPrefix)
              .Build();
      if (!aes_128_gcm_raw.ok()) {
        return aes_128_gcm_raw.status();
      }
      return std::make_unique<AesGcmParameters>(*aes_128_gcm_raw);
    }

    case DemId::kAes256GcmRaw: {
      util::StatusOr<AesGcmParameters> aes_256_gcm_raw =
          AesGcmParameters::Builder()
              .SetKeySizeInBytes(32)
              .SetIvSizeInBytes(12)
              .SetTagSizeInBytes(16)
              .SetVariant(AesGcmParameters::Variant::kNoPrefix)
              .Build();
      if (!aes_256_gcm_raw.ok()) {
        return aes_256_gcm_raw.status();
      }
      return std::make_unique<AesGcmParameters>(*aes_256_gcm_raw);
    }

    case DemId::kAes256SivRaw: {
      util::StatusOr<AesSivParameters> aes_256_siv_raw =
          AesSivParameters::Create(/*key_size_in_bytes=*/64,
                                   AesSivParameters::Variant::kNoPrefix);
      if (!aes_256_siv_raw.ok()) {
        return aes_256_siv_raw.status();
      }
      return std::make_unique<AesSivParameters>(*aes_256_siv_raw);
    }

    default:
      return util::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Cannot create DEM parameters for DEM id: ", dem_id_));
  }
}

bool EciesParameters::operator==(const Parameters& other) const {
  const EciesParameters* that = dynamic_cast<const EciesParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (curve_type_ != that->curve_type_) {
    return false;
  }
  if (hash_type_ != that->hash_type_) {
    return false;
  }
  if (point_format_ != that->point_format_) {
    return false;
  }
  if (dem_id_ != that->dem_id_) {
    return false;
  }
  if (salt_ != that->salt_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
