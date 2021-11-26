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

#include "tink/aead/internal/zero_copy_aes_gcm_boringssl.h"

#include <cstdint>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

util::StatusOr<std::unique_ptr<ZeroCopyAead>> ZeroCopyAesGcmBoringSsl::New(
    const util::SecretData &key) {
  util::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateAesGcmOneShotCrypter(key);
  if (!aead.ok()) {
    return aead.status();
  }
  return {absl::WrapUnique(new ZeroCopyAesGcmBoringSsl(*std::move(aead)))};
}

int64_t ZeroCopyAesGcmBoringSsl::MaxEncryptionSize(
    int64_t plaintext_size) const {
  return kIvSizeInBytes + aead_->CiphertextSize(plaintext_size);
}

util::StatusOr<int64_t> ZeroCopyAesGcmBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  const int64_t max_encryption_size = MaxEncryptionSize(plaintext.size());
  if (buffer.size() < max_encryption_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Encryption buffer too small; expected at least ",
                     max_encryption_size, " bytes, got ", buffer.size()));
  }
  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(plaintext, buffer_string)) {
    return util::Status(
        absl::StatusCode::kFailedPrecondition,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  util::Status res =
      subtle::Random::GetRandomBytes(buffer.subspan(0, kIvSizeInBytes));
  if (!res.ok()) {
    return res;
  }
  absl::string_view iv = buffer_string.substr(0, kIvSizeInBytes);
  absl::Span<char> raw_cipher_and_tag_buffer = buffer.subspan(kIvSizeInBytes);

  util::StatusOr<int64_t> written_bytes =
      aead_->Encrypt(plaintext, associated_data, iv, raw_cipher_and_tag_buffer);
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  return kIvSizeInBytes + *written_bytes;
}

int64_t ZeroCopyAesGcmBoringSsl::MaxDecryptionSize(
    int64_t ciphertext_size) const {
  const int64_t size = ciphertext_size - kIvSizeInBytes - kTagSizeInBytes;
  if (size <= 0) {
    return 0;
  }
  return size;
}

util::StatusOr<int64_t> ZeroCopyAesGcmBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  const size_t min_ciphertext_size = kIvSizeInBytes + kTagSizeInBytes;
  if (ciphertext.size() < min_ciphertext_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid ciphertext size; expected at least ",
                     min_ciphertext_size, " bytes, got ", ciphertext.size()));
  }

  const int64_t max_decryption_size = MaxDecryptionSize(ciphertext.size());
  if (buffer.size() < max_decryption_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Decryption buffer too small; expected at least ",
                     max_decryption_size, " bytes, got ", buffer.size()));
  }

  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(ciphertext, buffer_string)) {
    return util::Status(
        absl::StatusCode::kFailedPrecondition,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  auto iv = ciphertext.substr(0, kIvSizeInBytes);
  auto ciphertext_and_tag =
      ciphertext.substr(kIvSizeInBytes, ciphertext.size() - kIvSizeInBytes);
  return aead_->Decrypt(ciphertext_and_tag, associated_data, iv, buffer);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
