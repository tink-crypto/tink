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

#include "tink/hybrid/hpke_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

HpkeParameters::Builder& HpkeParameters::Builder::SetKemId(KemId kem_id) {
  kem_id_ = kem_id;
  return *this;
}

HpkeParameters::Builder& HpkeParameters::Builder::SetKdfId(KdfId kdf_id) {
  kdf_id_ = kdf_id;
  return *this;
}

HpkeParameters::Builder& HpkeParameters::Builder::SetAeadId(AeadId aead_id) {
  aead_id_ = aead_id;
  return *this;
}

HpkeParameters::Builder& HpkeParameters::Builder::SetVariant(Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<HpkeParameters> HpkeParameters::Builder::Build() {
  static const std::set<KemId>* supported_kem_ids = new std::set<KemId>(
      {KemId::kDhkemP256HkdfSha256, KemId::kDhkemP384HkdfSha384,
       KemId::kDhkemP521HkdfSha512, KemId::kDhkemX25519HkdfSha256});
  if (supported_kem_ids->find(kem_id_) == supported_kem_ids->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create HPKE parameters with unknown KEM ID.");
  }

  static const std::set<KdfId>* supported_kdf_ids = new std::set<KdfId>(
      {KdfId::kHkdfSha256, KdfId::kHkdfSha384, KdfId::kHkdfSha512});
  if (supported_kdf_ids->find(kdf_id_) == supported_kdf_ids->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create HPKE parameters with unknown KDF ID.");
  }

  static const std::set<AeadId>* supported_aead_ids = new std::set<AeadId>(
      {AeadId::kAesGcm128, AeadId::kAesGcm256, AeadId::kChaCha20Poly1305});
  if (supported_aead_ids->find(aead_id_) == supported_aead_ids->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create HPKE parameters with unknown AEAD ID.");
  }

  static const std::set<Variant>* supported_variants = new std::set<Variant>(
      {Variant::kTink, Variant::kCrunchy, Variant::kNoPrefix});
  if (supported_variants->find(variant_) == supported_variants->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create HPKE parameters with unknown variant.");
  }

  return HpkeParameters(kem_id_, kdf_id_, aead_id_, variant_);
}

bool HpkeParameters::operator==(const Parameters& other) const {
  const HpkeParameters* that = dynamic_cast<const HpkeParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (kem_id_ != that->kem_id_) {
    return false;
  }
  if (kdf_id_ != that->kdf_id_) {
    return false;
  }
  if (aead_id_ != that->aead_id_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
