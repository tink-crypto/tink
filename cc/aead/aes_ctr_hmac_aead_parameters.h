// Copyright 2024 Google LLC
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

#ifndef TINK_AEAD_AES_CTR_HMAC_AEAD_PARAMETERS_H_
#define TINK_AEAD_AES_CTR_HMAC_AEAD_PARAMETERS_H_

#include <memory>

#include "absl/types/optional.h"
#include "tink/aead/aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `AesCtrHmacAead`.
//
// The choices for the parameters values are restricted to a certain set of
// options:
//  - The AES key size accepts values of 16, 24, or 32 bytes. Current
//  implementation only offers support for 16-byte and 32-byte keys.
//  - The HMAC key size must be at least 16 bytes.
//  - The IV size accepts values between 12 and 16 bytes.
//  - The tag size accepts values between 10 and 64 bytes and depends on the
//  corresponding hash function as follows:
//    - SHA1 - at most 20 bytes tag size
//    - SHA224 - at most 28 bytes tag size
//    - SHA256 - at most 32 bytes tag size
//    - SHA384 - at most 48 bytes tag size
//    - SHA512 - at most 64 bytes tag size
//
// WARNING: Some of the values accepted by this class may
// actually be a superset of what is currently supported by the key type
// implementations. Specifying a larger set of value (i.e. 24-byte AES keys)
// aligns with a future possibility to add support for such parameters, if
// needed.
class AesCtrHmacAeadParameters : public AeadParameters {
 public:
  // Describes the output prefix prepended to the ciphertext.
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

  // Describes the hash algorithm used.
  enum class HashType : int {
    kSha1 = 1,
    kSha224 = 2,
    kSha256 = 3,
    kSha384 = 4,
    kSha512 = 5,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates AES-CTR-HMAC-AEAD parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetAesKeySizeInBytes(int aes_key_size);
    Builder& SetHmacKeySizeInBytes(int hmac_key_size);
    Builder& SetIvSizeInBytes(int iv_size);
    Builder& SetTagSizeInBytes(int tag_size);
    Builder& SetHashType(HashType hash_type);
    Builder& SetVariant(Variant variant);

    // Creates AES-CTR-HMAC-AEAD parameters object from this builder.
    util::StatusOr<AesCtrHmacAeadParameters> Build();

   private:
    absl::optional<int> aes_key_size_in_bytes_;
    absl::optional<int> hmac_key_size_in_bytes_;
    absl::optional<int> iv_size_in_bytes_;
    absl::optional<int> tag_size_in_bytes_;
    absl::optional<HashType> hash_type_;
    absl::optional<Variant> variant_;
  };

  // Copyable and movable.
  AesCtrHmacAeadParameters(const AesCtrHmacAeadParameters& other) = default;
  AesCtrHmacAeadParameters& operator=(const AesCtrHmacAeadParameters& other) =
      default;
  AesCtrHmacAeadParameters(AesCtrHmacAeadParameters&& other) = default;
  AesCtrHmacAeadParameters& operator=(AesCtrHmacAeadParameters&& other) =
      default;

  int GetAesKeySizeInBytes() const { return aes_key_size_in_bytes_; }

  int GetHmacKeySizeInBytes() const { return hmac_key_size_in_bytes_; }

  int GetIvSizeInBytes() const { return iv_size_in_bytes_; }

  int GetTagSizeInBytes() const { return tag_size_in_bytes_; }

  HashType GetHashType() const { return hash_type_; }

  Variant GetVariant() const { return variant_; }

  // Returns the size of the tag plus the size of the IV and of
  // the prefix with which this key prefixes every ciphertext.
  int CiphertextOverheadSizeInBytes() const;

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  AesCtrHmacAeadParameters(int aes_key_size_in_bytes,
                           int hmac_key_size_in_bytes, int iv_size_in_bytes,
                           int tag_size_in_bytes, HashType hash_type,
                           Variant variant)
      : aes_key_size_in_bytes_(aes_key_size_in_bytes),
        hmac_key_size_in_bytes_(hmac_key_size_in_bytes),
        iv_size_in_bytes_(iv_size_in_bytes),
        tag_size_in_bytes_(tag_size_in_bytes),
        hash_type_(hash_type),
        variant_(variant) {}

  int aes_key_size_in_bytes_;
  int hmac_key_size_in_bytes_;
  int iv_size_in_bytes_;
  int tag_size_in_bytes_;
  HashType hash_type_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_CTR_HMAC_AEAD_PARAMETERS_H_
