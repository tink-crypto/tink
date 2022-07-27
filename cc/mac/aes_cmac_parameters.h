// Copyright 2022 Google LLC
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

#ifndef TINK_MAC_AES_CMAC_PARAMETERS_H_
#define TINK_MAC_AES_CMAC_PARAMETERS_H_

#include <memory>

#include "tink/mac/mac_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `AesCmacKey`.
class AesCmacParameters : public MacParameters {
 public:
  // Describes the details of a MAC computation.
  //
  // The usual AES-CMAC key is used for variant `NO_PREFIX`. Other variants
  // slightly change how the MAC is computed, or add a prefix to every
  // computation depending on the key id.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to tag.
    kTink = 1,
    // Prepends '0x00<big endian key id>' to tag.
    kCrunchy = 2,
    // Appends a 0-byte to input message BEFORE computing the tag, then
    // prepends '0x00<big endian key id>' to tag.
    kLegacy = 3,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 4,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  AesCmacParameters(const AesCmacParameters& other) = default;
  AesCmacParameters& operator=(const AesCmacParameters& other) = default;
  AesCmacParameters(AesCmacParameters&& other) = default;
  AesCmacParameters& operator=(AesCmacParameters&& other) = default;

  // Creates a new AES-CMAC parameters object. Returns an error status if
  // `cryptographic_tag_size_in_bytes` falls outside [10,...,16].  Otherwise,
  // returns the parameters object.
  static util::StatusOr<AesCmacParameters> Create(
      int cryptographic_tag_size_in_bytes, Variant variant);

  Variant GetVariant() const { return variant_; }

  // Returns the size of the tag, which is computed cryptographically from the
  // message. Note that this may differ from the total size of the tag, as for
  // some keys, Tink prefixes the tag with a key dependent output prefix.
  int CryptographicTagSizeInBytes() const {
    return cryptographic_tag_size_in_bytes_;
  }

  // Returns the size of the cryptographic tag plus the size of the prefix with
  // which this key prefixes every cryptographic tag.
  int TotalTagSizeInBytes() const;

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  AesCmacParameters(int cryptographic_tag_size_in_bytes, Variant variant)
      : cryptographic_tag_size_in_bytes_(cryptographic_tag_size_in_bytes),
        variant_(variant) {}

  int cryptographic_tag_size_in_bytes_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_AES_CMAC_PARAMETERS_H_
