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

#ifndef TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_BORINGSSL_H_
#define TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "openssl/hpke.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class ABSL_DEPRECATED("Use HpkeContext.") HpkeEncryptBoringSsl {
 public:
  // Sets up an HPKE sender context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the sender context.
  //
  //   `params`: HPKE parameters proto (KEM, KDF, and AEAD).
  //   `recipient_public_key`: KEM-encoding of recipient public key.
  //   `context_info`: Application-specific context for key derivation.
  static util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>> New(
      const google::crypto::tink::HpkeParams& params,
      absl::string_view recipient_public_key, absl::string_view context_info);

  // NOTE:  The following method SHOULD ONLY BE USED FOR TESTING.
  //
  // Sets up an HPKE sender context.  Returns an error if initialization
  // fails.  Otherwise, returns a unique pointer to the sender context.
  //
  //   `params`: HPKE parameters proto (KEM, KDF, and AEAD).
  //   `recipient_public_key`: KEM-encoding of recipient public key.
  //   `context_info`: Application-specific context for key derivation.
  //   `seed_for_testing`: Seed used to match test vector values.
  static util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>> NewForTesting(
      const google::crypto::tink::HpkeParams& params,
      absl::string_view recipient_public_key, absl::string_view context_info,
      absl::string_view seed_for_testing);

  // Performs an AEAD encryption of `plaintext` with `associated_data`.
  // Returns an error if encryption fails.  Otherwise, returns the ciphertext
  // appended to the encapsulated key.
  util::StatusOr<std::string> EncapsulateKeyThenEncrypt(
      absl::string_view plaintext, absl::string_view associated_data);

  const std::string& encapsulated_key() const { return encapsulated_key_; }

 private:
  HpkeEncryptBoringSsl() {}

  util::Status Init(const google::crypto::tink::HpkeParams& params,
                    absl::string_view recipient_public_key,
                    absl::string_view context_info);

  util::Status InitForTesting(const google::crypto::tink::HpkeParams& params,
                              absl::string_view recipient_public_key,
                              absl::string_view context_info,
                              absl::string_view seed_for_testing);

  bssl::ScopedEVP_HPKE_CTX sender_ctx_;
  std::string encapsulated_key_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_BORINGSSL_H_
