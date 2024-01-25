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

#ifndef TINK_SIGNATURE_RSA_SSA_PSS_PARAMETERS_H_
#define TINK_SIGNATURE_RSA_SSA_PSS_PARAMETERS_H_

#include <string>

#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/parameters.h"
#include "tink/signature/signature_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class RsaSsaPssParameters : public SignatureParameters {
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

  // Describes the hash algorithm used for computation.
  enum class HashType : int {
    kSha256 = 1,
    kSha384 = 2,
    kSha512 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates RsaSsaPss parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetModulusSizeInBits(int modulus_size_in_bits);
    Builder& SetPublicExponent(const BigInteger& public_exponent);
    Builder& SetSigHashType(HashType sig_hash_type);
    Builder& SetMgf1HashType(HashType mgf1_hash_type);
    Builder& SetSaltLengthInBytes(int salt_length_in_bytes);
    Builder& SetVariant(Variant variant);

    // Creates RsaSsaPss parameters object from this builder.
    util::StatusOr<RsaSsaPssParameters> Build();

   private:
    static BigInteger CreateDefaultPublicExponent();

    absl::optional<int> modulus_size_in_bits_ = absl::nullopt;
    // Defaults to F4.
    BigInteger public_exponent_ = CreateDefaultPublicExponent();
    absl::optional<HashType> sig_hash_type_ = absl::nullopt;
    absl::optional<HashType> mgf1_hash_type_ = absl::nullopt;
    absl::optional<int> salt_length_in_bytes_ = absl::nullopt;
    absl::optional<Variant> variant_ = absl::nullopt;
  };

  // Copyable and movable.
  RsaSsaPssParameters(const RsaSsaPssParameters& other) = default;
  RsaSsaPssParameters& operator=(const RsaSsaPssParameters& other) = default;
  RsaSsaPssParameters(RsaSsaPssParameters&& other) = default;
  RsaSsaPssParameters& operator=(RsaSsaPssParameters&& other) = default;

  int GetModulusSizeInBits() const { return modulus_size_in_bits_; }

  const BigInteger& GetPublicExponent() const { return public_exponent_; }

  HashType GetSigHashType() const { return sig_hash_type_; }

  HashType GetMgf1HashType() const { return mgf1_hash_type_; }

  int GetSaltLengthInBytes() const { return salt_length_in_bytes_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit RsaSsaPssParameters(int modulus_size_in_bits,
                               const BigInteger& public_exponent,
                               HashType sig_hash_type, HashType mgf1_hash_type,
                               int salt_length_in_bytes, Variant variant)
      : modulus_size_in_bits_(modulus_size_in_bits),
        public_exponent_(public_exponent),
        sig_hash_type_(sig_hash_type),
        mgf1_hash_type_(mgf1_hash_type),
        salt_length_in_bytes_(salt_length_in_bytes),
        variant_(variant) {}

  int modulus_size_in_bits_;
  BigInteger public_exponent_;
  HashType sig_hash_type_;
  HashType mgf1_hash_type_;
  int salt_length_in_bytes_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_RSA_SSA_PSS_PARAMETERS_H_
