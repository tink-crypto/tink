// Copyright 2021 Google LLC.
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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_AEAD_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_AEAD_H_

#include <cstdint>

#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

///////////////////////////////////////////////////////////////////////////////
// The interface for authenticated encryption with associated data.
// Implementations of this interface are secure against adaptive
// chosen ciphertext attacks. Encryption with associated data ensures
// authenticity and integrity of that data, but not its secrecy.
// (see RFC 5116, https://tools.ietf.org/html/rfc5116)
//
// This implementation expects the user to provide a contiguous block
// of memory and writes the Encrypt and Decrypt results in the block.
// This requires the user to avoid mutating this block during calls to
// Encrypt and Decrypt and aims to reduce the latency associated with
// copying strings from one location to another.
class ZeroCopyAead {
 public:
  virtual ~ZeroCopyAead() = default;

  // Returns the maximum buffer size needed for encryption. The actual
  // size of the written cypertext may be smaller.
  virtual int64_t MaxEncryptionSize(int64_t plaintext_size) const = 0;

  // Encrypts `plaintext` with `associated_data` as associated data,
  // and returns the size of the ciphertext that is written in `buffer`.
  // `buffer` size must be at least MaxEncryptionSize to guarantee
  // enough space for encryption.
  // The ciphertext allows for checking authenticity and integrity
  // of the associated data, but does not guarantee its secrecy.
  virtual crypto::tink::util::StatusOr<int64_t> Encrypt(
      absl::string_view plaintext, absl::string_view associated_data,
      absl::Span<char> buffer) const = 0;

  // Returns an upper bound on the size of the plaintext based on
  // `ciphertext_size`. The actual size of the written plaintext may be smaller.
  // The returned value is always >= 0.
  virtual int64_t MaxDecryptionSize(int64_t ciphertext_size) const = 0;

  // Decrypts `ciphertext` with `associated_data` as associated data,
  // and returns the size of the plaintext that is written in `buffer`.
  // `buffer` size must be at least MaxDecryptionSize to guarantee
  // enough space for decryption.
  // If the authentication tag does not validate, `buffer` is zeroed.
  // The decryption verifies the authenticity and integrity of the
  // associated data, but there are no guarantees wrt. secrecy of
  // that data.
  virtual crypto::tink::util::StatusOr<int64_t> Decrypt(
      absl::string_view ciphertext, absl::string_view associated_data,
      absl::Span<char> buffer) const = 0;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_AEAD_H_
