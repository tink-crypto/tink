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

#ifndef TINK_SIGNATURE_ECDSA_PUBLIC_KEY_H_
#define TINK_SIGNATURE_ECDSA_PUBLIC_KEY_H_

#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/ec_point.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/signature_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the verify function for an ECDSA digital signature
// primitive.
class EcdsaPublicKey : public SignaturePublicKey {
 public:
  // Copyable and movable.
  EcdsaPublicKey(const EcdsaPublicKey& other) = default;
  EcdsaPublicKey& operator=(const EcdsaPublicKey& other) = default;
  EcdsaPublicKey(EcdsaPublicKey&& other) = default;
  EcdsaPublicKey& operator=(EcdsaPublicKey&& other) = default;

  static util::StatusOr<EcdsaPublicKey> Create(
      const EcdsaParameters& parameters, const EcPoint& public_point,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  const EcPoint& GetPublicPoint(PartialKeyAccessToken token) const {
    return public_point_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  const EcdsaParameters& GetParameters() const override { return parameters_; }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

 private:
  explicit EcdsaPublicKey(const EcdsaParameters& parameters,
                          const EcPoint& public_point,
                          absl::optional<int> id_requirement,
                          absl::string_view output_prefix)
      : parameters_(parameters),
        public_point_(public_point),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  EcdsaParameters parameters_;
  EcPoint public_point_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ECDSA_PUBLIC_KEY_H_
