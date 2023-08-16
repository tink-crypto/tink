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

#ifndef TINK_SIGNATURE_ED25519_PRIVATE_KEY_H_
#define TINK_SIGNATURE_ED25519_PRIVATE_KEY_H_

#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class Ed25519PrivateKey : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  Ed25519PrivateKey(const Ed25519PrivateKey& other) = default;
  Ed25519PrivateKey& operator=(const Ed25519PrivateKey& other) = default;
  Ed25519PrivateKey(Ed25519PrivateKey&& other) = default;
  Ed25519PrivateKey& operator=(Ed25519PrivateKey&& other) = default;

  // Creates a new Ed25519 private key from `private_key_bytes`. Returns an
  // error if `public_key` does not belong to the same key pair as
  // `private_key_bytes`.
  static util::StatusOr<Ed25519PrivateKey> Create(
      const Ed25519PublicKey& public_key,
      const RestrictedData& private_key_bytes, PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKeyBytes(PartialKeyAccessToken token) const {
    return private_key_bytes_;
  }

  const Ed25519PublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

 private:
  explicit Ed25519PrivateKey(const Ed25519PublicKey& public_key,
                             const RestrictedData& private_key_bytes)
      : public_key_(public_key), private_key_bytes_(private_key_bytes) {}

  Ed25519PublicKey public_key_;
  RestrictedData private_key_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ED25519_PRIVATE_KEY_H_
