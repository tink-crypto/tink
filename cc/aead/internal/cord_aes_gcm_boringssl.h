// Copyright 2020 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_AEAD_INTERNAL_CORD_AES_GCM_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_CORD_AES_GCM_BORINGSSL_H_

#include <memory>
#include <utility>

#include "openssl/evp.h"
#include "tink/aead/cord_aead.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

class CordAesGcmBoringSsl : public CordAead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<CordAead>> New(
      const util::SecretData& key_value);

  crypto::tink::util::StatusOr<absl::Cord> Encrypt(
      absl::Cord plaintext, absl::Cord associated_data) const override;

  crypto::tink::util::StatusOr<absl::Cord> Decrypt(
      absl::Cord ciphertext, absl::Cord associated_data) const override;

 private:
  explicit CordAesGcmBoringSsl(
      internal::SslUniquePtr<EVP_CIPHER_CTX> partial_context,
      const util::SecretData& key)
      : partial_context_(std::move(partial_context)), key_(key) {}

  // Partially-initialized EVP_CIPHER_CTX context that is copied for every
  // Encrypt/Decrypt operation.
  internal::SslUniquePtr<EVP_CIPHER_CTX> partial_context_;
  util::SecretData key_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_CORD_AES_GCM_BORINGSSL_H_
