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

#include "tink/subtle/xchacha20_poly1305_boringssl.h"

#include <algorithm>
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
#include "tink/aead.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/internal/util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

constexpr int kNonceSizeInBytes = 24;
constexpr int kTagSizeInBytes = 16;

util::StatusOr<std::unique_ptr<Aead>> XChacha20Poly1305BoringSsl::New(
    util::SecretData key) {
  auto status = internal::CheckFipsCompatibility<XChacha20Poly1305BoringSsl>();
  if (!status.ok()) {
    return status;
  }
  util::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateXchacha20Poly1305OneShotCrypter(key);
  if (!aead.ok()) {
    return aead.status();
  }
  std::unique_ptr<Aead> aead_impl =
      absl::WrapUnique(new XChacha20Poly1305BoringSsl(*std::move(aead)));
  return std::move(aead_impl);
}

util::StatusOr<std::string> XChacha20Poly1305BoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  const int64_t kCiphertextSize =
      kNonceSizeInBytes + aead_->CiphertextSize(plaintext.size());
  std::string ct;
  ResizeStringUninitialized(&ct, kCiphertextSize);
  util::Status res =
      Random::GetRandomBytes(absl::MakeSpan(ct).subspan(0, kNonceSizeInBytes));
  if (!res.ok()) {
    return res;
  }
  auto nonce = absl::string_view(ct).substr(0, kNonceSizeInBytes);
  auto ciphertext_and_tag_buffer =
      absl::MakeSpan(ct).subspan(kNonceSizeInBytes);
  util::StatusOr<int64_t> written_bytes = aead_->Encrypt(
      plaintext, associated_data, nonce, ciphertext_and_tag_buffer);
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  return ct;
}

util::StatusOr<std::string> XChacha20Poly1305BoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  if (ciphertext.size() < kNonceSizeInBytes + kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Ciphertext too short; expected at least ",
                                     kNonceSizeInBytes + kTagSizeInBytes,
                                     " got ", ciphertext.size()));
  }
  const int64_t kPlaintextSize =
      aead_->PlaintextSize(ciphertext.size() - kNonceSizeInBytes);
  std::string plaintext;
  ResizeStringUninitialized(&plaintext, kPlaintextSize);
  auto nonce = ciphertext.substr(0, kNonceSizeInBytes);
  auto encrypted = ciphertext.substr(kNonceSizeInBytes);
  util::StatusOr<int64_t> written_bytes = aead_->Decrypt(
      encrypted, associated_data, nonce, absl::MakeSpan(plaintext));
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  return plaintext;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
