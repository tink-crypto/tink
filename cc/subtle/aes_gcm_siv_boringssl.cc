// Copyright 2018 Google Inc.
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

#include "tink/subtle/aes_gcm_siv_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

util::StatusOr<std::unique_ptr<Aead>> AesGcmSivBoringSsl::New(
    const util::SecretData& key) {
  auto status = internal::CheckFipsCompatibility<AesGcmSivBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  util::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateAesGcmSivOneShotCrypter(key);
  if (!aead.ok()) {
    return aead.status();
  }

  return {absl::WrapUnique(new AesGcmSivBoringSsl(*std::move(aead)))};
}

util::StatusOr<std::string> AesGcmSivBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
  const int64_t kCiphertextSize =
      kIvSizeInBytes + aead_->CiphertextSize(plaintext.size());
  std::string ct;
  ResizeStringUninitialized(&ct, kCiphertextSize);
  util::Status res =
      Random::GetRandomBytes(absl::MakeSpan(ct).subspan(0, kIvSizeInBytes));
  if (!res.ok()) {
    return res;
  }
  auto nonce = absl::string_view(ct).substr(0, kIvSizeInBytes);
  auto ciphertext_and_tag_buffer = absl::MakeSpan(ct).subspan(kIvSizeInBytes);
  util::StatusOr<int64_t> written_bytes = aead_->Encrypt(
      plaintext, additional_data, nonce, ciphertext_and_tag_buffer);
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  return ct;
}

util::StatusOr<std::string> AesGcmSivBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  if (ciphertext.size() < kIvSizeInBytes + kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Ciphertext too short; expected at least ",
                                     kIvSizeInBytes + kTagSizeInBytes, " got ",
                                     ciphertext.size()));
  }
  const int64_t kPlaintextSize =
      aead_->PlaintextSize(ciphertext.size() - kIvSizeInBytes);
  std::string plaintext;
  ResizeStringUninitialized(&plaintext, kPlaintextSize);
  auto nonce = ciphertext.substr(0, kIvSizeInBytes);
  auto encrypted = ciphertext.substr(kIvSizeInBytes);
  util::StatusOr<int64_t> written_bytes = aead_->Decrypt(
      encrypted, additional_data, nonce, absl::MakeSpan(plaintext));
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  return plaintext;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
