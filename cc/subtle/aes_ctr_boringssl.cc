// Copyright 2017 Google Inc.
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

#include "cc/subtle/aes_ctr_boringssl.h"

#include <string>
#include <vector>

#include "cc/subtle/ind_cpa_cipher.h"
#include "cc/subtle/random.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "openssl/err.h"
#include "openssl/evp.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {
namespace subtle {

static const EVP_CIPHER* GetCipherForKeySize(uint32_t size_in_bytes) {
  switch (size_in_bytes) {
    case 16:
      return EVP_aes_128_ctr();
    case 24:
      return EVP_aes_192_ctr();
    case 32:
      return EVP_aes_256_ctr();
    default:
      return nullptr;
  }
}

AesCtrBoringSsl::AesCtrBoringSsl(absl::string_view key_value,
                                 uint8_t iv_size, const EVP_CIPHER* cipher)
    : key_(key_value), iv_size_(iv_size), cipher_(cipher) {}

util::StatusOr<std::unique_ptr<IndCpaCipher>> AesCtrBoringSsl::New(
    absl::string_view key_value, uint8_t iv_size) {
  const EVP_CIPHER* cipher = GetCipherForKeySize(key_value.size());
  if (cipher == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }
  if (iv_size < MIN_IV_SIZE_IN_BYTES || iv_size > BLOCK_SIZE) {
    return util::Status(util::error::INTERNAL, "invalid iv size");
  }
  std::unique_ptr<IndCpaCipher> ind_cpa_cipher(
      new AesCtrBoringSsl(key_value, iv_size, cipher));
  return std::move(ind_cpa_cipher);
}

util::StatusOr<std::string> AesCtrBoringSsl::Encrypt(
    absl::string_view plaintext) const {
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }
  const std::string iv = Random::GetRandomBytes(iv_size_);
  // OpenSSL expects that the IV must be a full block.
  uint8_t iv_block[BLOCK_SIZE];
  memset(iv_block, 0, sizeof(iv_block));
  memcpy(iv_block, iv.data(), iv.size());
  int ret = EVP_EncryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                               reinterpret_cast<const uint8_t*>(key_.data()),
                               iv_block);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "could not initialize ctx");
  }
  size_t ciphertext_size = iv.size() + plaintext.size();
  // Allocates 1 byte more than necessary because we may potentially access
  // &ct[ciphertext_size] causing vector range check error.
  std::vector<uint8_t> ct(ciphertext_size + 1);
  memcpy(&ct[0], reinterpret_cast<const uint8_t*>(iv.data()), iv.size());
  size_t written = iv.size();
  int len;
  ret = EVP_EncryptUpdate(ctx.get(), &ct[written], &len,
                          reinterpret_cast<const uint8_t*>(plaintext.data()),
                          plaintext.size());
  if (ret != 1) {
    util::Status(util::error::INTERNAL, "encryption failed");
  }
  written += len;

  if (written != ciphertext_size) {
    util::Status(util::error::INTERNAL, "incorrect ciphertext size");
  }
  return std::string(reinterpret_cast<const char*>(&ct[0]), written);
}

util::StatusOr<std::string> AesCtrBoringSsl::Decrypt(
    absl::string_view ciphertext) const {
  if (ciphertext.size() < iv_size_) {
    return util::Status(util::error::INTERNAL, "ciphertext too short");
  }

  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }

  // Initialise key and IV
  uint8_t iv_block[BLOCK_SIZE];
  memset(iv_block, 0, sizeof(iv_block));
  memcpy(iv_block, &ciphertext.data()[0], iv_size_);
  int ret = EVP_DecryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                               reinterpret_cast<const uint8_t*>(key_.data()),
                               iv_block);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize key or iv");
  }

  size_t plaintext_size = ciphertext.size() - iv_size_;
  // Allocates 1 byte more than necessary because we may potentially access
  // &pt[plaintext_size] causing vector range check error.
  std::vector<uint8_t> pt(plaintext_size + 1);
  size_t read = iv_size_;
  size_t written = 0;
  int len;
  ret = EVP_DecryptUpdate(
      ctx.get(), &pt[written], &len,
      reinterpret_cast<const uint8_t*>(&ciphertext.data()[read]),
      plaintext_size);
  if (ret != 1) {
    util::Status(util::error::INTERNAL, "decryption failed");
  }
  written += len;

  if (written != plaintext_size) {
    return util::Status(util::error::INTERNAL, "incorrect plaintext size");
  }
  return std::string(reinterpret_cast<const char*>(&pt[0]), written);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
