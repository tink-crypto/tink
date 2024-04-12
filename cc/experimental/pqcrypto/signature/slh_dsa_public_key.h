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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SLH_DSA_PUBLIC_KEY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SLH_DSA_PUBLIC_KEY_H_

#include <string>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/signature_public_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the verification function for the SLH-DSA digital signature
// primitive.
class SlhDsaPublicKey : public SignaturePublicKey {
 public:
  // Copyable and movable.
  SlhDsaPublicKey(const SlhDsaPublicKey& other) = default;
  SlhDsaPublicKey& operator=(const SlhDsaPublicKey& other) = default;
  SlhDsaPublicKey(SlhDsaPublicKey&& other) = default;
  SlhDsaPublicKey& operator=(SlhDsaPublicKey&& other) = default;

  // Creates a new SLH-DSA public key from `public_key_bytes`. If the
  // `parameters` specify a variant that uses a prefix, then `id_requirement` is
  // used to compute this prefix.
  static util::StatusOr<SlhDsaPublicKey> Create(
      const SlhDsaParameters& parameters, absl::string_view public_key_bytes,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  absl::string_view GetPublicKeyBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return public_key_bytes_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  const SlhDsaParameters& GetParameters() const override { return parameters_; }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

 private:
  explicit SlhDsaPublicKey(const SlhDsaParameters& parameters,
                           absl::string_view public_key_bytes,
                           absl::optional<int> id_requirement,
                           absl::string_view output_prefix)
      : parameters_(parameters),
        public_key_bytes_(public_key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  SlhDsaParameters parameters_;
  std::string public_key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SLH_DSA_PUBLIC_KEY_H_
