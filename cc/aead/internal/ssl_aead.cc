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
#include "tink/aead/internal/ssl_aead.h"

#include <cstdint>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

const int kXchacha20Poly1305TagSizeInBytes = 16;
const int kAesGcmTagSizeInBytes = 16;

namespace {

// Returns an EVP_AEAD cipher or an error if `key_size_in_bytes` is invalid.
util::StatusOr<const EVP_AEAD *> GetAesGcmSivAeadCipherForKeySize(
    int key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aead_aes_128_gcm_siv();
    case 32:
      return EVP_aead_aes_256_gcm_siv();
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat(
              "Invalid key size; valid values are {16, 32} bytes, got ",
              key_size_in_bytes));
  }
}

// Implementation of the one-shot AEAD cypter. This is purposely internal to an
// anonymous namespace to disallow direct use of this class other than through
// the Create* functions below.
class BoringSslOneShotAeadImpl : public SslOneShotAead {
 public:
  BoringSslOneShotAeadImpl(internal::SslUniquePtr<EVP_AEAD_CTX> context,
                           size_t tag_size)
      : context_(std::move(context)), tag_size_(tag_size) {}

  util::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::string_view iv,
                                  absl::Span<char> out) const override {
    // BoringSSL expects a non-null pointer for additional_data,
    // regardless of whether the size is 0.
    plaintext = internal::EnsureStringNonNull(plaintext);
    associated_data = internal::EnsureStringNonNull(associated_data);
    iv = internal::EnsureStringNonNull(iv);

    if (BuffersOverlap(plaintext, absl::string_view(out.data(), out.size()))) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Plaintext and output buffer must not overlap");
    }

    if (out.size() < plaintext.size() + tag_size_) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Output buffer too small; expected at least ",
                       plaintext.size() + tag_size_, " got ", out.size()));
    }
    size_t out_len = 0;
    if (!EVP_AEAD_CTX_seal(
            context_.get(), reinterpret_cast<uint8_t *>(&out[0]), &out_len,
            out.size(), reinterpret_cast<const uint8_t *>(iv.data()), iv.size(),
            reinterpret_cast<const uint8_t *>(plaintext.data()),
            plaintext.size(),
            /*ad=*/reinterpret_cast<const uint8_t *>(associated_data.data()),
            /*ad_len=*/associated_data.size())) {
      return util::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Encryption failed: ", internal::GetSslErrors()));
    }

    return out_len;
  }

  util::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::string_view iv,
                                  absl::Span<char> out) const override {
    ciphertext = internal::EnsureStringNonNull(ciphertext);
    associated_data = internal::EnsureStringNonNull(associated_data);
    iv = internal::EnsureStringNonNull(iv);

    if (BuffersOverlap(ciphertext, absl::string_view(out.data(), out.size()))) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Ciphertext and output buffer must not overlap");
    }

    if (ciphertext.size() < tag_size_) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Ciphertext buffer too small; expected at least ",
                       tag_size_, " got ", ciphertext.size()));
    }

    if (out.size() < ciphertext.size() - tag_size_) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Output buffer too small; expected at least ",
                       ciphertext.size() - tag_size_, " got ", out.size()));
    }

    uint8_t buffer_if_size_is_zero;
    uint8_t *buffer_ptr = &buffer_if_size_is_zero;
    if (!out.empty()) {
      buffer_ptr = reinterpret_cast<uint8_t *>(&out[0]);
    }

    size_t out_len = 0;
    if (!EVP_AEAD_CTX_open(
            context_.get(), buffer_ptr, &out_len, out.size(),
            reinterpret_cast<const uint8_t *>(iv.data()), iv.size(),
            reinterpret_cast<const uint8_t *>(ciphertext.data()),
            ciphertext.size(),
            /*ad=*/reinterpret_cast<const uint8_t *>(associated_data.data()),
            /*ad_len=*/associated_data.size())) {
      return util::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Encryption failed: ", internal::GetSslErrors()));
    }

    return out_len;
  }

  const internal::SslUniquePtr<EVP_AEAD_CTX> context_;
  const size_t tag_size_;
};

// One shot implementing AES-GCM.
class BoringSslAesGcmOneShotAead : public BoringSslOneShotAeadImpl {
 public:
  explicit BoringSslAesGcmOneShotAead(
      internal::SslUniquePtr<EVP_AEAD_CTX> context)
      : BoringSslOneShotAeadImpl(std::move(context), kAesGcmTagSizeInBytes) {}

  int64_t CiphertextSize(int64_t plaintext_length) const override {
    return plaintext_length + kAesGcmTagSizeInBytes;
  }

  int64_t PlaintextSize(int64_t ciphertext_length) const override {
    if (ciphertext_length < kAesGcmTagSizeInBytes) {
      return 0;
    }
    return ciphertext_length - kAesGcmTagSizeInBytes;
  }
};

// One shot implementing AES-GCM-SIV.
using BoringSslAesGcmSivOneShotAead = BoringSslAesGcmOneShotAead;

// One shot implementing XCHACHA-POLY-1305.
class BoringSslXchacha20Poly1305OneShotAead : public BoringSslOneShotAeadImpl {
 public:
  explicit BoringSslXchacha20Poly1305OneShotAead(
      internal::SslUniquePtr<EVP_AEAD_CTX> context)
      : BoringSslOneShotAeadImpl(std::move(context),
                                 kXchacha20Poly1305TagSizeInBytes) {}

  int64_t CiphertextSize(int64_t plaintext_length) const override {
    return plaintext_length + kXchacha20Poly1305TagSizeInBytes;
  }

  int64_t PlaintextSize(int64_t ciphertext_length) const override {
    if (ciphertext_length < kXchacha20Poly1305TagSizeInBytes) {
      return 0;
    }
    return ciphertext_length - kXchacha20Poly1305TagSizeInBytes;
  }
};

}  // namespace

util::StatusOr<std::unique_ptr<SslOneShotAead>> CreateAesGcmOneShotCrypter(
    const util::SecretData &key) {
  util::StatusOr<const EVP_AEAD *> aead_cipher =
      GetAesGcmAeadForKeySize(key.size());
  if (!aead_cipher.ok()) {
    return aead_cipher.status();
  }

  internal::SslUniquePtr<EVP_AEAD_CTX> context(EVP_AEAD_CTX_new(
      *aead_cipher, key.data(), key.size(), kAesGcmTagSizeInBytes));
  if (context == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EVP_AEAD_CTX_new initialization Failed: ",
                                     internal::GetSslErrors()));
  }
  return {absl::make_unique<BoringSslAesGcmOneShotAead>(std::move(context))};
}

util::StatusOr<std::unique_ptr<SslOneShotAead>> CreateAesGcmSivOneShotCrypter(
    const util::SecretData &key) {
  util::StatusOr<const EVP_AEAD *> aead_cipher =
      GetAesGcmSivAeadCipherForKeySize(key.size());
  if (!aead_cipher.ok()) {
    return aead_cipher.status();
  }
  internal::SslUniquePtr<EVP_AEAD_CTX> context(EVP_AEAD_CTX_new(
      *aead_cipher, key.data(), key.size(), kAesGcmTagSizeInBytes));
  if (context == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EVP_AEAD_CTX_new initialization Failed: ",
                                     internal::GetSslErrors()));
  }
  return {absl::make_unique<BoringSslAesGcmSivOneShotAead>(std::move(context))};
}

util::StatusOr<std::unique_ptr<SslOneShotAead>>
CreateXchacha20Poly1305OneShotCrypter(const util::SecretData &key) {
  if (key.size() != 32) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid key size; valid values are {32} bytes, got ",
                     key.size()));
  }

  internal::SslUniquePtr<EVP_AEAD_CTX> context(
      EVP_AEAD_CTX_new(EVP_aead_xchacha20_poly1305(), key.data(), key.size(),
                       kAesGcmTagSizeInBytes));
  if (context == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EVP_AEAD_CTX_new initialization Failed: ",
                                     internal::GetSslErrors()));
  }
  return {absl::make_unique<BoringSslXchacha20Poly1305OneShotAead>(
      std::move(context))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
