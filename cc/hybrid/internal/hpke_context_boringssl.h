// Copyright 2022 Google LLC
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

#ifndef TINK_HYBRID_INTERNAL_HPKE_CONTEXT_BORINGSSL_H_
#define TINK_HYBRID_INTERNAL_HPKE_CONTEXT_BORINGSSL_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

struct SenderHpkeContextBoringSsl;

class HpkeContextBoringSsl {
 public:
  // Sets up an HPKE sender context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the sender context.
  //
  //   `params`: HPKE parameters (KEM, KDF, and AEAD).
  //   `recipient_public_key`: KEM-encoding of recipient public key.
  //   `info`: Application-specific context for key derivation.
  static crypto::tink::util::StatusOr<SenderHpkeContextBoringSsl>
  SetupSender(const HpkeParams& params, absl::string_view recipient_public_key,
              absl::string_view info);

  // Sets up an HPKE recipient context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the recipient context.
  //
  //   `params`: HPKE parameters (KEM, KDF, and AEAD).
  //   `recipient_private_key`: Recipient private key.
  //   `encapsulated_key`: Encapsulated key.
  //   `info`: Application-specific context for key derivation.
  static crypto::tink::util::StatusOr<std::unique_ptr<HpkeContextBoringSsl>>
  SetupRecipient(const HpkeParams& params,
                 const util::SecretData& recipient_private_key,
                 absl::string_view encapsulated_key, absl::string_view info);

  // Performs an AEAD encryption of `plaintext` with `associated_data`. Returns
  // an error if encryption fails.  Otherwise, returns the ciphertext.
  crypto::tink::util::StatusOr<std::string> Seal(
      absl::string_view plaintext, absl::string_view associated_data);

  // Performs an AEAD decryption of `ciphertext` with `associated_data`. Returns
  // an error if decryption fails.  Otherwise, returns the plaintext.
  crypto::tink::util::StatusOr<std::string> Open(
      absl::string_view ciphertext, absl::string_view associated_data);

  // Exports `secret_length` bytes of secret material using `exporter_context`
  // for the input context.  Returns an error if export fails.  Otherwise,
  // returns a secret of the requested length.
  crypto::tink::util::StatusOr<util::SecretData> Export(
      absl::string_view exporter_context, int64_t secret_length);

 protected:
  explicit HpkeContextBoringSsl(SslUniquePtr<EVP_HPKE_CTX> context)
      : context_(std::move(context)) {}

 private:
  SslUniquePtr<EVP_HPKE_CTX> context_;
};

struct SenderHpkeContextBoringSsl {
  std::unique_ptr<HpkeContextBoringSsl> context;
  std::string encapsulated_key;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_CONTEXT_BORINGSSL_H_
