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

#ifndef TINK_HYBRID_ECIES_PARAMETERS_H_
#define TINK_HYBRID_ECIES_PARAMETERS_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hybrid_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class EciesParameters : public HybridParameters {
 public:
  // Description of the output prefix prepended to the ciphertext.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to ciphertext.
    kTink = 1,
    // Prepends '0x00<big endian key id>' to ciphertext.
    kCrunchy = 2,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 3,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Elliptic curve type used for KEM.
  enum class CurveType : int {
    kNistP256 = 1,
    kNistP384 = 2,
    kNistP521 = 3,
    kX25519 = 4,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Hash algorithm used for KEM.
  enum class HashType : int {
    kSha1 = 1,
    kSha256 = 2,
    kSha224 = 3,
    kSha384 = 4,
    kSha512 = 5,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Elliptic curve point format.
  enum class PointFormat : int {
    kCompressed = 1,
    kUncompressed = 2,
    // Same as `kUncompressed`, but without the leading '\x04' prefix byte.
    // Only used by Crunchy. DO NOT USE unless you are a Crunchy user migrating
    // to Tink.
    kLegacyUncompressed = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Data encapsulation mechanism (DEM) identifiers. Each entry should
  // correspond to either an allowed AEAD or an allowed Deterministic AEAD.
  enum class DemId : int {
    kAes128GcmRaw = 1,
    kAes256GcmRaw = 2,
    kAes256SivRaw = 3,
    // TODO: b/319155153 - Add DEM id for XChaCha20-Poly1305.
    // TODO: b/319156273 - Add DEM ids for AES-CTR-HMAC.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates ECIES parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetCurveType(CurveType curve);
    Builder& SetHashType(HashType hash);
    Builder& SetNistCurvePointFormat(PointFormat format);
    Builder& SetDemId(DemId dem_id);
    Builder& SetSalt(absl::string_view salt);
    Builder& SetVariant(Variant variant);

    // Creates ECIES parameters object from this builder.
    util::StatusOr<EciesParameters> Build();

   private:
    CurveType curve_type_;
    HashType hash_type_;
    absl::optional<PointFormat> point_format_ = absl::nullopt;
    DemId dem_id_;
    absl::optional<std::string> salt_ = absl::nullopt;
    Variant variant_;
  };

  // Copyable and movable.
  EciesParameters(const EciesParameters& other) = default;
  EciesParameters& operator=(const EciesParameters& other) = default;
  EciesParameters(EciesParameters&& other) = default;
  EciesParameters& operator=(EciesParameters&& other) = default;

  CurveType GetCurveType() const { return curve_type_; }

  HashType GetHashType() const { return hash_type_; }

  absl::optional<PointFormat> GetNistCurvePointFormat() const {
    return point_format_;
  }

  DemId GetDemId() const { return dem_id_; }

  absl::optional<absl::string_view> GetSalt() const { return salt_; }

  Variant GetVariant() const { return variant_; }

  util::StatusOr<std::unique_ptr<Parameters>> CreateDemParameters() const;

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit EciesParameters(CurveType curve_type, HashType hash_type,
                           absl::optional<PointFormat> point_format,
                           DemId dem_id, absl::optional<absl::string_view> salt,
                           Variant variant)
      : curve_type_(curve_type),
        hash_type_(hash_type),
        point_format_(point_format),
        dem_id_(dem_id),
        salt_(salt),
        variant_(variant) {}

  CurveType curve_type_;
  HashType hash_type_;
  absl::optional<PointFormat> point_format_;
  DemId dem_id_;
  absl::optional<std::string> salt_ = absl::nullopt;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_PARAMETERS_H_
