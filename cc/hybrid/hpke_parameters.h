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

#ifndef TINK_HYBRID_HPKE_PARAMETERS_H_
#define TINK_HYBRID_HPKE_PARAMETERS_H_

#include "tink/hybrid/hybrid_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class HpkeParameters : public HybridParameters {
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

  // HPKE KEM identifiers specified in
  // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
  enum class KemId : int {
    kDhkemP256HkdfSha256 = 1,
    kDhkemP384HkdfSha384 = 2,
    kDhkemP521HkdfSha512 = 3,
    kDhkemX25519HkdfSha256 = 4,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // HPKE KDF identifiers specified in
  // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
  enum class KdfId : int {
    kHkdfSha256 = 1,
    kHkdfSha384 = 2,
    kHkdfSha512 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // HPKE AEAD identifiers specified in
  // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
  enum class AeadId : int {
    kAesGcm128 = 1,
    kAesGcm256 = 2,
    kChaChaPoly1305 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates HPKE parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetKemId(KemId kem_id);
    Builder& SetKdfId(KdfId kdf_id);
    Builder& SetAeadId(AeadId aead_id);
    Builder& SetVariant(Variant variant);

    // Creates HPKE parameters object from this builder.
    util::StatusOr<HpkeParameters> Build();

   private:
    KemId kem_id_;
    KdfId kdf_id_;
    AeadId aead_id_;
    Variant variant_;
  };

  // Copyable and movable.
  HpkeParameters(const HpkeParameters& other) = default;
  HpkeParameters& operator=(const HpkeParameters& other) = default;
  HpkeParameters(HpkeParameters&& other) = default;
  HpkeParameters& operator=(HpkeParameters&& other) = default;

  KemId GetKemId() const { return kem_id_; }

  KdfId GetKdfId() const { return kdf_id_; }

  AeadId GetAeadId() const { return aead_id_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit HpkeParameters(KemId kem_id, KdfId kdf_id, AeadId aead_id,
                          Variant variant)
      : kem_id_(kem_id),
        kdf_id_(kdf_id),
        aead_id_(aead_id),
        variant_(variant) {}

  KemId kem_id_;
  KdfId kdf_id_;
  AeadId aead_id_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_HPKE_PARAMETERS_H_
