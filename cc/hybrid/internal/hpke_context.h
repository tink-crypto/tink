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

#ifndef TINK_HYBRID_INTERNAL_HPKE_CONTEXT_H_
#define TINK_HYBRID_INTERNAL_HPKE_CONTEXT_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/hybrid/internal/hpke_context_boringssl.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Pair of string views for an HPKE payload (encapsulated key and ciphertext).
struct HpkePayloadView {
  HpkePayloadView(absl::string_view encapsulated_key,
                  absl::string_view ciphertext)
      : encapsulated_key(encapsulated_key), ciphertext(ciphertext) {}

  absl::string_view encapsulated_key;
  absl::string_view ciphertext;
};

// Creates HPKE payload `encapsulated_key` || `ciphertext` (i.e., Tink hybrid
// encryption wire format described at
// https://developers.google.com/tink/wire-format#hybrid_encryption).
std::string ConcatenatePayload(absl::string_view encapsulated_key,
                               absl::string_view ciphertext);

// Splits `payload` into an `HpkePayloadView` struct.  The `kem` parameter is
// used to determine how to split the payload.
//
// WARNING: The string pointed to by `payload` must outlive the returned object.
crypto::tink::util::StatusOr<HpkePayloadView> SplitPayload(
    const HpkeKem& kem, absl::string_view payload);

// Represents an HPKE context for either a sender or a recipient.
class HpkeContext {
 public:
  // Sets up an HPKE sender context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the sender context.
  //
  //   `params`: HPKE parameters (KEM, KDF, and AEAD).
  //   `recipient_public_key`: KEM-encoding of recipient public key.
  //   `info`: Application-specific context for key derivation.
  static crypto::tink::util::StatusOr<std::unique_ptr<HpkeContext>> SetupSender(
      const HpkeParams& params, absl::string_view recipient_public_key,
      absl::string_view info);

  // Sets up an HPKE recipient context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the recipient context.
  //
  //   `params`: HPKE parameters (KEM, KDF, and AEAD).
  //   `recipient_private_key`: Recipient private key.
  //   `encapsulated_key`: Encapsulated key.
  //   `info`: Application-specific context for key derivation.
  static crypto::tink::util::StatusOr<std::unique_ptr<HpkeContext>>
  SetupRecipient(const HpkeParams& params,
                 const util::SecretData& recipient_private_key,
                 absl::string_view encapsulated_key, absl::string_view info);

  absl::string_view EncapsulatedKey() const {
    return encapsulated_key_;
  }

  // Performs an AEAD encryption of `plaintext` with `associated_data`. Returns
  // an error if encryption fails.  Otherwise, returns the ciphertext.
  crypto::tink::util::StatusOr<std::string> Seal(
      absl::string_view plaintext, absl::string_view associated_data) {
    return context_->Seal(plaintext, associated_data);
  }

  // Performs an AEAD decryption of `ciphertext` with `associated_data`. Returns
  // an error if decryption fails.  Otherwise, returns the plaintext.
  crypto::tink::util::StatusOr<std::string> Open(
      absl::string_view ciphertext, absl::string_view associated_data) {
    return context_->Open(ciphertext, associated_data);
  }

  // Exports `secret_length` bytes of secret material using `exporter_context`
  // for the input context.  Returns an error if export fails.  Otherwise,
  // returns a secret of the requested length.
  crypto::tink::util::StatusOr<util::SecretData> Export(
      absl::string_view exporter_context, size_t secret_length) {
    return context_->Export(exporter_context, secret_length);
  }

 private:
  explicit HpkeContext(absl::string_view encapsulated_key,
                       std::unique_ptr<HpkeContextBoringSsl> context)
      : encapsulated_key_(encapsulated_key), context_(std::move(context)) {}

  const std::string encapsulated_key_;
  const std::unique_ptr<HpkeContextBoringSsl> context_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_CONTEXT_H_
