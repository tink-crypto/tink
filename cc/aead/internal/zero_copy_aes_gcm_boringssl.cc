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

#include "tink/aead/internal/zero_copy_aes_gcm_boringssl.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/aead.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<std::unique_ptr<ZeroCopyAead>> ZeroCopyAesGcmBoringSsl::New(
    const util::SecretData &key) {
  util::StatusOr<const EVP_AEAD *> aead =
      internal::GetAesGcmAeadForKeySize(key.size());
  if (!aead.ok()) {
    return aead.status();
  }
  internal::SslUniquePtr<EVP_AEAD_CTX> ctx(EVP_AEAD_CTX_new(
      *aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH));
  if (ctx == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "could not initialize EVP_AEAD_CTX");
  }
  return {absl::WrapUnique(new ZeroCopyAesGcmBoringSsl(std::move(ctx)))};
}

uint64_t ZeroCopyAesGcmBoringSsl::MaxEncryptionSize(
    int64_t plaintext_size) const {
  return kIvSizeInBytes + plaintext_size + kTagSizeInBytes;
}

crypto::tink::util::StatusOr<int64_t> ZeroCopyAesGcmBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  if (buffer.size() < MaxEncryptionSize(plaintext.size())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Encryption buffer too small");
  }
  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(plaintext, buffer_string)) {
    return util::Status(
        util::error::FAILED_PRECONDITION,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  // TODO(b/198004452): Add GetRandomBytes(absl::Span<char>) to avoid copy.
  std::string iv = subtle::Random::GetRandomBytes(kIvSizeInBytes);
  std::memcpy(buffer.data(), iv.data(), kIvSizeInBytes);

  size_t len;
  if (EVP_AEAD_CTX_seal(
          ctx_.get(), reinterpret_cast<uint8_t *>(&buffer[kIvSizeInBytes]),
          &len, plaintext.size() + kTagSizeInBytes,
          reinterpret_cast<const uint8_t *>(&buffer[0]), kIvSizeInBytes,
          reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(),
          reinterpret_cast<const uint8_t *>(associated_data.data()),
          associated_data.size()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Encryption failed");
  }
  return kIvSizeInBytes + len;
}

uint64_t ZeroCopyAesGcmBoringSsl::MaxDecryptionSize(
    int64_t ciphertext_size) const {
  return ciphertext_size - kIvSizeInBytes;
}

crypto::tink::util::StatusOr<int64_t> ZeroCopyAesGcmBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  if (buffer.size() < MaxDecryptionSize(ciphertext.size())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Decryption buffer too small");
  }
  if (ciphertext.size() < kIvSizeInBytes + kTagSizeInBytes) {
    return util::Status(util::error::INVALID_ARGUMENT, "Ciphertext too short");
  }
  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(ciphertext, buffer_string)) {
    return util::Status(
        util::error::FAILED_PRECONDITION,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  size_t len;
  if (EVP_AEAD_CTX_open(
          ctx_.get(), reinterpret_cast<uint8_t *>(&buffer[0]), &len,
          buffer.size(),
          // The IV is the first |kIvSizeInBytes| bytes of |ciphertext|.
          reinterpret_cast<const uint8_t *>(ciphertext.data()), kIvSizeInBytes,
          // The input is the remainder.
          reinterpret_cast<const uint8_t *>(ciphertext.data()) + kIvSizeInBytes,
          ciphertext.size() - kIvSizeInBytes,
          reinterpret_cast<const uint8_t *>(associated_data.data()),
          associated_data.size()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Authentication failed");
  }
  return len;
}

bool ZeroCopyAesGcmBoringSsl::BuffersOverlap(absl::string_view first,
                                             absl::string_view second) {
  // first begins within second's buffer.
  bool first_begins_in_second =
      std::less_equal<const char *>{}(second.begin(), first.begin()) &&
      std::less<const char *>{}(first.begin(), second.end());

  // second begins within first's buffer.
  bool second_begins_in_first =
      std::less_equal<const char *>{}(first.begin(), second.begin()) &&
      std::less<const char *>{}(second.begin(), first.end());

  return first_begins_in_second || second_begins_in_first;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
