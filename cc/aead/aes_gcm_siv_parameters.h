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

#ifndef TINK_AEAD_AES_GCM_SIV_PARAMETERS_H_
#define TINK_AEAD_AES_GCM_SIV_PARAMETERS_H_

#include "tink/aead/aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `AesGcmSivKey`.
class AesGcmSivParameters : public AeadParameters {
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
  AesGcmSivParameters(const AesGcmSivParameters& other) = default;
  AesGcmSivParameters& operator=(const AesGcmSivParameters& other) = default;
  AesGcmSivParameters(AesGcmSivParameters&& other) = default;
  AesGcmSivParameters& operator=(AesGcmSivParameters&& other) = default;

  // Creates a new AES-GCM-SIV parameters object. Returns an error if either
  // `key_size_in_bytes` or `variant` is invalid.
  static util::StatusOr<AesGcmSivParameters> Create(int key_size_in_bytes,
                                                    Variant variant);

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  AesGcmSivParameters(int key_size_in_bytes, Variant variant)
      : key_size_in_bytes_(key_size_in_bytes), variant_(variant) {}

  int key_size_in_bytes_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_GCM_SIV_PARAMETERS_H_
