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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SLH_DSA_PARAMETERS_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SLH_DSA_PARAMETERS_H_

#include "tink/parameters.h"
#include "tink/signature/signature_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the parameters sets for the Stateless Hash-Based Digital
// Signature Standard (SLH-DSA) described at
// https://csrc.nist.gov/pubs/fips/205/ipd.
//
// Note that only the SLH-DSA-SHA2-128s set is currently supported.
class SlhDsaParameters : public SignatureParameters {
 public:
  // Describes the output prefix prepended to the signature.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to signature.
    kTink = 1,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 2,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Description of the hash function used for this algorithm.
  enum class HashType : int {
    // The 128-bit security level variant uses SHA256. The 192-bit and 256-bit
    // variants require both SHA-256 and SHA-512 in their implementation.
    kSha2 = 1,
    kShake = 2,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Description of the signature type. kFastSigning parameters sets
  // have significantly faster signing, but kSmallSignature come with faster
  // verification and smaller signatures.
  enum class SignatureType : int {
    kFastSigning = 1,
    kSmallSignature = 2,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  SlhDsaParameters(const SlhDsaParameters& other) = default;
  SlhDsaParameters& operator=(const SlhDsaParameters& other) = default;
  SlhDsaParameters(SlhDsaParameters&& other) = default;
  SlhDsaParameters& operator=(SlhDsaParameters&& other) = default;

  // Creates SLH-DSA parameters instances.
  static util::StatusOr<SlhDsaParameters> Create(HashType hash_type,
                                                 int private_key_size_in_bytes,
                                                 SignatureType signature_type,
                                                 Variant variant);

  HashType GetHashType() const { return hash_type_; }
  int GetPrivateKeySizeInBytes() const { return private_key_size_in_bytes_; }
  SignatureType GetSignatureType() const { return signature_type_; }
  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit SlhDsaParameters(HashType hash_type, int private_key_size_in_bytes,
                            SignatureType signature_type, Variant variant)
      : hash_type_(hash_type),
        private_key_size_in_bytes_(private_key_size_in_bytes),
        signature_type_(signature_type),
        variant_(variant) {}

  HashType hash_type_;
  int private_key_size_in_bytes_;
  SignatureType signature_type_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SLH_DSA_PARAMETERS_H_
