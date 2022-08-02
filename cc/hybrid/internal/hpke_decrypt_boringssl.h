// Copyright 2021 Google LLC
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

#ifndef TINK_HYBRID_INTERNAL_HPKE_DECRYPT_BORINGSSL_H_
#define TINK_HYBRID_INTERNAL_HPKE_DECRYPT_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_key_boringssl.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class ABSL_DEPRECATED("Use HpkeContext.") HpkeDecryptBoringSsl {
 public:
  // Sets up an HPKE recipient context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the recipient context.
  //
  //   `params`: HPKE parameters proto (KEM, KDF, and AEAD).
  //   `hpke_key`: Recipient private key.
  //   `encapsulated_key`: Encapsulated key.
  //   `context_info`: Application-specific context for key derivation.
  static util::StatusOr<std::unique_ptr<HpkeDecryptBoringSsl>> New(
      const google::crypto::tink::HpkeParams& params,
      const HpkeKeyBoringSsl& hpke_key, absl::string_view encapsulated_key,
      absl::string_view context_info);

  // Performs an AEAD decryption of `ciphertext` with `associated_data`.
  // Returns an error if decryption fails.  Otherwise, returns the plaintext.
  util::StatusOr<std::string> Decrypt(absl::string_view ciphertext,
                                      absl::string_view associated_data);

 private:
  HpkeDecryptBoringSsl() {}

  util::Status Init(const google::crypto::tink::HpkeParams& params,
                    const HpkeKeyBoringSsl& hpke_key,
                    absl::string_view encapsulated_key,
                    absl::string_view context_info);

  bssl::ScopedEVP_HPKE_CTX recipient_ctx_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_DECRYPT_BORINGSSL_H_
