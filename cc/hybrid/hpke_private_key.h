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

#ifndef TINK_HYBRID_HPKE_PRIVATE_KEY_H_
#define TINK_HYBRID_HPKE_PRIVATE_KEY_H_

#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/hybrid_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the decryption function for an HPKE hybrid encryption
// primitive.
class HpkePrivateKey : public HybridPrivateKey {
 public:
  // Copyable and movable.
  HpkePrivateKey(const HpkePrivateKey& other) = default;
  HpkePrivateKey& operator=(const HpkePrivateKey& other) = default;
  HpkePrivateKey(HpkePrivateKey&& other) = default;
  HpkePrivateKey& operator=(HpkePrivateKey&& other) = default;

  // Creates a new HPKE private key from `private_key_bytes`. Returns an
  // error if `public_key` does not belong to the same key pair as
  // `private_key_bytes`.
  static util::StatusOr<HpkePrivateKey> Create(
      const HpkePublicKey& public_key, const RestrictedData& private_key_bytes,
      PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKeyBytes(PartialKeyAccessToken token) const {
    return private_key_bytes_;
  }

  const HpkePublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

 private:
  explicit HpkePrivateKey(const HpkePublicKey& public_key,
                          const RestrictedData& private_key_bytes)
      : public_key_(public_key), private_key_bytes_(private_key_bytes) {}

  HpkePublicKey public_key_;
  RestrictedData private_key_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_HPKE_PRIVATE_KEY_H_
