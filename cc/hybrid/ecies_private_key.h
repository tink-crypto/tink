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

#ifndef TINK_HYBRID_ECIES_PRIVATE_KEY_H_
#define TINK_HYBRID_ECIES_PRIVATE_KEY_H_

#include "absl/types/optional.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/hybrid_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the decryption function for an ECIES hybrid encryption
// primitive.
class EciesPrivateKey : public HybridPrivateKey {
 public:
  // Copyable and movable.
  EciesPrivateKey(const EciesPrivateKey& other) = default;
  EciesPrivateKey& operator=(const EciesPrivateKey& other) = default;
  EciesPrivateKey(EciesPrivateKey&& other) = default;
  EciesPrivateKey& operator=(EciesPrivateKey&& other) = default;

  static util::StatusOr<EciesPrivateKey> CreateForNistCurve(
      const EciesPublicKey& public_key,
      const RestrictedBigInteger& private_key_value,
      PartialKeyAccessToken token);

  static util::StatusOr<EciesPrivateKey> CreateForCurveX25519(
      const EciesPublicKey& public_key, const RestrictedData& private_key_bytes,
      PartialKeyAccessToken token);

  absl::optional<RestrictedBigInteger> GetNistPrivateKeyValue(
      PartialKeyAccessToken token) const {
    return private_key_value_;
  }

  absl::optional<RestrictedData> GetX25519PrivateKeyBytes(
      PartialKeyAccessToken token) const {
    return private_key_bytes_;
  }

  const EciesPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

 private:
  // Creates a NIST curve-based ECIES private key.
  explicit EciesPrivateKey(const EciesPublicKey& public_key,
                           const RestrictedBigInteger& private_key_value)
      : public_key_(public_key),
        private_key_value_(private_key_value),
        private_key_bytes_(absl::nullopt) {}

  // Creates an X25519-based ECIES private key.
  explicit EciesPrivateKey(const EciesPublicKey& public_key,
                           const RestrictedData& private_key_bytes)
      : public_key_(public_key),
        private_key_value_(absl::nullopt),
        private_key_bytes_(private_key_bytes) {}

  EciesPublicKey public_key_;
  absl::optional<RestrictedBigInteger> private_key_value_;
  absl::optional<RestrictedData> private_key_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_PRIVATE_KEY_H_
