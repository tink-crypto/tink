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

#ifndef TINK_SIGNATURE_ECDSA_PRIVATE_KEY_H_
#define TINK_SIGNATURE_ECDSA_PRIVATE_KEY_H_

#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the sign function for an ECDSA digital signature
// primitive.
class EcdsaPrivateKey : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  EcdsaPrivateKey(const EcdsaPrivateKey& other) = default;
  EcdsaPrivateKey& operator=(const EcdsaPrivateKey& other) = default;
  EcdsaPrivateKey(EcdsaPrivateKey&& other) = default;
  EcdsaPrivateKey& operator=(EcdsaPrivateKey&& other) = default;

  static util::StatusOr<EcdsaPrivateKey> Create(
      const EcdsaPublicKey& public_key,
      const RestrictedBigInteger& private_key_value,
      PartialKeyAccessToken token);

  const RestrictedBigInteger& GetPrivateKeyValue(
      PartialKeyAccessToken token) const {
    return private_key_value_;
  }

  const EcdsaPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

 private:
  explicit EcdsaPrivateKey(const EcdsaPublicKey& public_key,
                           const RestrictedBigInteger& private_key_value)
      : public_key_(public_key), private_key_value_(private_key_value) {}

  EcdsaPublicKey public_key_;
  RestrictedBigInteger private_key_value_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ECDSA_PRIVATE_KEY_H_
