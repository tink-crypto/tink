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

#include "tink/signature/ed25519_private_key.h"

#include "openssl/crypto.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

util::StatusOr<Ed25519PrivateKey> Ed25519PrivateKey::Create(
    const Ed25519PublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  if (private_key_bytes.size() != 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ed25519 private key length must be 32 bytes.");
  }
  // Confirm that private key and public key are a valid Ed25519 key pair.
  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key(util::SecretDataFromStringView(
          private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get())));
  absl::string_view expected_public_key = public_key.GetPublicKeyBytes(token);
  if (CRYPTO_memcmp(expected_public_key.data(), (*key_pair)->public_key.data(),
                    32) != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid public key for private key bytes.");
  }
  return Ed25519PrivateKey(public_key, private_key_bytes);
}

bool Ed25519PrivateKey::operator==(const Key& other) const {
  const Ed25519PrivateKey* that =
      dynamic_cast<const Ed25519PrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (public_key_ != that->public_key_) {
    return false;
  }
  return private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
