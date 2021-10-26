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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_AES_GCM_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_AES_GCM_BORINGSSL_H_

#include <memory>
#include <utility>

#include "absl/base/macros.h"
#include "openssl/aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

class ZeroCopyAesGcmBoringSsl : public ZeroCopyAead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<ZeroCopyAead>> New(
      const util::SecretData &key);

  uint64_t MaxEncryptionSize(int64_t plaintext_size) const override;

  crypto::tink::util::StatusOr<int64_t> Encrypt(
      absl::string_view plaintext, absl::string_view associated_data,
      absl::Span<char> buffer) const override;

  uint64_t MaxDecryptionSize(int64_t ciphertext_size) const override;

  crypto::tink::util::StatusOr<int64_t> Decrypt(
      absl::string_view ciphertext, absl::string_view associated_data,
      absl::Span<char> buffer) const override;

  // TODO(b/198004452): Move to common library.
  static bool BuffersOverlap(absl::string_view first, absl::string_view second);

 private:
  static constexpr int kIvSizeInBytes = 12;
  static constexpr int kTagSizeInBytes = 16;

  explicit ZeroCopyAesGcmBoringSsl(bssl::UniquePtr<EVP_AEAD_CTX> ctx)
      : ctx_(std::move(ctx)) {}

  bssl::UniquePtr<EVP_AEAD_CTX> ctx_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_AES_GCM_BORINGSSL_H_
