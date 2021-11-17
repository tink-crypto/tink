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
#ifndef TINK_AEAD_INTERNAL_SSL_AEAD_H_
#define TINK_AEAD_INTERNAL_SSL_AEAD_H_

#include <cstdint>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

ABSL_CONST_INIT extern const int kXchacha20Poly1305TagSizeInBytes;
// Tag size for both AES-GCM and AES-GCM-SIV.
ABSL_CONST_INIT extern const int kAesGcmTagSizeInBytes;

// Interface for one-shot AEAD crypters.
class SslOneShotAead {
 public:
  virtual ~SslOneShotAead() = default;

  // Returns the size of the ciphertext from `plaintext_length`.
  virtual int64_t CiphertextSize(int64_t plaintext_length) const = 0;

  // Encrypts `plaintext` with `associated_data` and `iv`, and writes the output
  // to `out`. The implementation places both the raw ciphertext and the
  // resulting tag in `out`, so the caller must make sure it has sufficient
  // capacity. There should be no overlap between `plaintext` and `out`. In
  // particular, in-place encryption is not supported.
  virtual util::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                          absl::string_view associated_data,
                                          absl::string_view iv,
                                          absl::Span<char> out) const = 0;

  // Returns the size of the plaintext given `ciphertext_length`. This is always
  // >= 0.
  virtual int64_t PlaintextSize(int64_t ciphertext_length) const = 0;

  // Decrypts `ciphertext` with `associated_data` and `iv`, and writes the
  // plaintext to `out`. `ciphertext` contains the raw ciphertext and the tag.
  // There should be no overlap between `ciphertext` and `out`. In particular,
  // in-place decryption is not supported.
  virtual util::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                          absl::string_view associated_data,
                                          absl::string_view iv,
                                          absl::Span<char> out) const = 0;
};

// Create one-shot crypters for the supported algorithms.
util::StatusOr<std::unique_ptr<SslOneShotAead>> CreateAesGcmOneShotCrypter(
    const util::SecretData &key);
util::StatusOr<std::unique_ptr<SslOneShotAead>> CreateAesGcmSivOneShotCrypter(
    const util::SecretData &key);
util::StatusOr<std::unique_ptr<SslOneShotAead>>
CreateXchacha20Poly1305OneShotCrypter(const util::SecretData &key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_SSL_AEAD_H_
