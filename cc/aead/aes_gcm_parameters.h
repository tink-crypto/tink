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

#ifndef TINK_AEAD_AES_GCM_PARAMETERS_H_
#define TINK_AEAD_AES_GCM_PARAMETERS_H_

#include "tink/aead/aead_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `AesGcmKey`.
class AesGcmParameters : public AeadParameters {
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

  // Creates AES-GCM parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetKeySizeInBytes(int key_size);
    Builder& SetIvSizeInBytes(int iv_size);
    Builder& SetTagSizeInBytes(int tag_size);
    Builder& SetVariant(Variant variant);

    // Creates AES-GCM parameters object from this builder.
    util::StatusOr<AesGcmParameters> Build();

   private:
    int key_size_in_bytes_;
    int iv_size_in_bytes_;
    int tag_size_in_bytes_;
    Variant variant_;
  };

  // Copyable and movable.
  AesGcmParameters(const AesGcmParameters& other) = default;
  AesGcmParameters& operator=(const AesGcmParameters& other) = default;
  AesGcmParameters(AesGcmParameters&& other) = default;
  AesGcmParameters& operator=(AesGcmParameters&& other) = default;

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  int IvSizeInBytes() const { return iv_size_in_bytes_; }

  int TagSizeInBytes() const { return tag_size_in_bytes_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  AesGcmParameters(int key_size_in_bytes, int iv_size_in_bytes,
                   int tag_size_in_bytes, Variant variant)
      : key_size_in_bytes_(key_size_in_bytes),
        iv_size_in_bytes_(iv_size_in_bytes),
        tag_size_in_bytes_(tag_size_in_bytes),
        variant_(variant) {}

  int key_size_in_bytes_;
  int iv_size_in_bytes_;
  int tag_size_in_bytes_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_GCM_PARAMETERS_H_
