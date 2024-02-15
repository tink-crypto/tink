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

#ifndef TINK_DAEAD_AES_SIV_PARAMETERS_H_
#define TINK_DAEAD_AES_SIV_PARAMETERS_H_

#include "tink/daead/deterministic_aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `AesSivKey`.
class AesSivParameters : public DeterministicAeadParameters {
 public:
  // Description of the output prefix prepended to the ciphertext.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to the ciphertext.
    kTink = 1,
    // Prepends '0x00<big endian key id>' to the ciphertext.
    kCrunchy = 2,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 3,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  AesSivParameters(const AesSivParameters& other) = default;
  AesSivParameters& operator=(const AesSivParameters& other) = default;
  AesSivParameters(AesSivParameters&& other) = default;
  AesSivParameters& operator=(AesSivParameters&& other) = default;

  // Creates `AesSivParameters` object from `key_size_in_bytes` and `variant`.
  // Only allows 32-, 48-, and 64-byte key sizes as specified in RFC 5297.
  static util::StatusOr<AesSivParameters> Create(int key_size_in_bytes,
                                                 Variant variant);

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  AesSivParameters(int key_size_in_bytes, Variant variant)
      : key_size_in_bytes_(key_size_in_bytes), variant_(variant) {}

  int key_size_in_bytes_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_AES_SIV_PARAMETERS_H_
