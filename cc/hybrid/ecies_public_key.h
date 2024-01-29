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

#ifndef TINK_HYBRID_ECIES_PUBLIC_KEY_H_
#define TINK_HYBRID_ECIES_PUBLIC_KEY_H_

#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/hybrid_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the encryption function for an ECIES hybrid encryption
// primitive.
class EciesPublicKey : public HybridPublicKey {
 public:
  // Copyable and movable.
  EciesPublicKey(const EciesPublicKey& other) = default;
  EciesPublicKey& operator=(const EciesPublicKey& other) = default;
  EciesPublicKey(EciesPublicKey&& other) = default;
  EciesPublicKey& operator=(EciesPublicKey&& other) = default;

  static util::StatusOr<EciesPublicKey> CreateForNistCurve(
      const EciesParameters& parameters, const EcPoint& point,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  static util::StatusOr<EciesPublicKey> CreateForCurveX25519(
      const EciesParameters& parameters, absl::string_view public_key_bytes,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  absl::optional<EcPoint> GetNistCurvePoint(PartialKeyAccessToken token) const {
    return point_;
  }

  absl::optional<absl::string_view> GetX25519CurvePointBytes(
      PartialKeyAccessToken token) const {
    return public_key_bytes_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  const EciesParameters& GetParameters() const override { return parameters_; }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

 private:
  // Creates a NIST curve-based ECIES public key.
  explicit EciesPublicKey(const EciesParameters& parameters,
                          const EcPoint& point,
                          absl::optional<int> id_requirement,
                          absl::string_view output_prefix)
      : parameters_(parameters),
        point_(point),
        public_key_bytes_(absl::nullopt),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  // Creates an X25519-based ECIES public key.
  explicit EciesPublicKey(const EciesParameters& parameters,
                          absl::string_view public_key_bytes,
                          absl::optional<int> id_requirement,
                          absl::string_view output_prefix)
      : parameters_(parameters),
        point_(absl::nullopt),
        public_key_bytes_(public_key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  EciesParameters parameters_;
  absl::optional<EcPoint> point_;
  absl::optional<std::string> public_key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_PUBLIC_KEY_H_
