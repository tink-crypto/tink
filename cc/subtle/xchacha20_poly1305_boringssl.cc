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

#include <cstdint>
#include <string>
#include <vector>

#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/aead.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
const bool IsValidKeySize(uint32_t size_in_bytes) {
  return size_in_bytes == 32;
}
}  // namespace

util::StatusOr<std::unique_ptr<Aead>> XChacha20Poly1305BoringSsl::New(
    util::SecretData key) {
  auto status = internal::CheckFipsCompatibility<XChacha20Poly1305BoringSsl>();
  if (!status.ok()) return status;

  if (!IsValidKeySize(key.size())) {
    return util::Status(util::error::INVALID_ARGUMENT, "Invalid key size");
  }

  const EVP_AEAD* cipher = EVP_aead_xchacha20_poly1305();
  if (cipher == nullptr) {
    return util::Status(util::error::INTERNAL, "Failed to get EVP_AEAD");
  }
  return std::unique_ptr<Aead>(
      new XChacha20Poly1305BoringSsl(std::move(key), cipher));
}

util::StatusOr<std::string> XChacha20Poly1305BoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
  internal::SslUniquePtr<EVP_AEAD_CTX> ctx(
      EVP_AEAD_CTX_new(aead_, reinterpret_cast<const uint8_t*>(key_.data()),
                       key_.size(), kTagSize));
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_AEAD_CTX");
  }

  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);
  additional_data = internal::EnsureStringNonNull(additional_data);

  const std::string nonce = Random::GetRandomBytes(kNonceSize);
  if (nonce.size() != kNonceSize) {
    return util::Status(util::error::INTERNAL,
                        "Failed to get enough random bytes for nonce");
  }

  size_t ciphertext_size = nonce.size() + plaintext.size() + kTagSize;

  // Write the nonce in the output buffer.
  std::string ct = nonce;
  ResizeStringUninitialized(&ct, ciphertext_size);
  size_t written = nonce.size();

  // Encrypt the plaintext and store it after the nonce.
  size_t out_len = 0;
  int ret = EVP_AEAD_CTX_seal(
      ctx.get(), reinterpret_cast<uint8_t*>(&ct[written]), &out_len,
      ciphertext_size - written, reinterpret_cast<const uint8_t*>(nonce.data()),
      nonce.size(), reinterpret_cast<const uint8_t*>(plaintext.data()),
      plaintext.size(),
      reinterpret_cast<const uint8_t*>(additional_data.data()),
      additional_data.size());
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "EVP_AEAD_CTX_seal failed");
  }
  written += out_len;

  // Verify that all the expected data has been written.
  if (written != ciphertext_size) {
    return util::Status(util::error::INTERNAL, "Incorrect ciphertext size");
  }
  return ct;
}

util::StatusOr<std::string> XChacha20Poly1305BoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for additional_data,
  // regardless of whether the size is 0.
  additional_data = internal::EnsureStringNonNull(additional_data);

  if (ciphertext.size() < kNonceSize + kTagSize) {
    return util::Status(util::error::INVALID_ARGUMENT, "Ciphertext too short");
  }

  internal::SslUniquePtr<EVP_AEAD_CTX> ctx(
      EVP_AEAD_CTX_new(aead_, reinterpret_cast<const uint8_t*>(key_.data()),
                       key_.size(), kTagSize));
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_AEAD_CTX");
  }

  std::string out;
  size_t out_size = ciphertext.size() - kNonceSize - kTagSize;
  ResizeStringUninitialized(&out, out_size);

  absl::string_view nonce = ciphertext.substr(0, kNonceSize);
  absl::string_view encrypted =
      ciphertext.substr(kNonceSize, out_size + kTagSize);

  size_t len = 0;
  int ret = EVP_AEAD_CTX_open(
      ctx.get(), reinterpret_cast<uint8_t*>(&out[0]), &len, out_size,
      reinterpret_cast<const uint8_t*>(nonce.data()), nonce.size(),
      reinterpret_cast<const uint8_t*>(encrypted.data()), encrypted.size(),
      reinterpret_cast<const uint8_t*>(additional_data.data()),
      additional_data.size());
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "EVP_AEAD_CTX_open failed");
  }

  if (len != out_size) {
    return util::Status(util::error::INTERNAL, "Incorrect output size");
  }

  return out;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
