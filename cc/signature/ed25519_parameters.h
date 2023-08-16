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

#ifndef TINK_SIGNATURE_ED25519_PARAMETERS_H_
#define TINK_SIGNATURE_ED25519_PARAMETERS_H_

#include "tink/signature/signature_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class Ed25519Parameters : public SignatureParameters {
 public:
  // Description of the output prefix prepended to the signature.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to signature.
    kTink = 1,
    // Prepends '0x00<big endian key id>' to signature.
    kCrunchy = 2,
    // Appends a 0-byte to input message BEFORE computing the signature, then
    // prepends '0x00<big endian key id>' to signature.
    kLegacy = 3,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 4,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  Ed25519Parameters(const Ed25519Parameters& other) = default;
  Ed25519Parameters& operator=(const Ed25519Parameters& other) = default;
  Ed25519Parameters(Ed25519Parameters&& other) = default;
  Ed25519Parameters& operator=(Ed25519Parameters&& other) = default;

  // Creates a new Ed25519 parameters object unless `variant` is invalid.
  static util::StatusOr<Ed25519Parameters> Create(Variant variant);

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit Ed25519Parameters(Variant variant) : variant_(variant) {}

  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ED25519_PARAMETERS_H_
