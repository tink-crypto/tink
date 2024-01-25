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

#ifndef TINK_SIGNATURE_ECDSA_PARAMETERS_H_
#define TINK_SIGNATURE_ECDSA_PARAMETERS_H_

#include "absl/types/optional.h"
#include "tink/parameters.h"
#include "tink/signature/signature_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class EcdsaParameters : public SignatureParameters {
 public:
  // Describes the output prefix prepended to the signature.
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

  enum class CurveType : int {
    kNistP256 = 1,
    kNistP384 = 2,
    kNistP521 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  enum class HashType : int {
    kSha256 = 1,
    kSha384 = 2,
    kSha512 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  enum class SignatureEncoding : int {
    kDer = 1,
    kIeeeP1363 = 2,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates Ecdsa parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetCurveType(CurveType curve_type);
    Builder& SetHashType(HashType hash_type);
    Builder& SetSignatureEncoding(SignatureEncoding signature_encoding);
    Builder& SetVariant(Variant variant);

    // Creates Ecdsa parameters object from this builder.
    util::StatusOr<EcdsaParameters> Build();

   private:
    absl::optional<CurveType> curve_type_;
    absl::optional<HashType> hash_type_;
    absl::optional<SignatureEncoding> signature_encoding_;
    absl::optional<Variant> variant_;
  };

  // Copyable and movable.
  EcdsaParameters(const EcdsaParameters& other) = default;
  EcdsaParameters& operator=(const EcdsaParameters& other) = default;
  EcdsaParameters(EcdsaParameters&& other) = default;
  EcdsaParameters& operator=(EcdsaParameters&& other) = default;

  CurveType GetCurveType() const { return curve_type_; }
  HashType GetHashType() const { return hash_type_; }
  SignatureEncoding GetSignatureEncoding() const { return signature_encoding_; }
  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit EcdsaParameters(CurveType curve_type, HashType hash_type,
                           SignatureEncoding signature_encoding,
                           Variant variant)
      : curve_type_(curve_type),
        hash_type_(hash_type),
        signature_encoding_(signature_encoding),
        variant_(variant) {}

  CurveType curve_type_;
  HashType hash_type_;
  SignatureEncoding signature_encoding_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ECDSA_PARAMETERS_H_
