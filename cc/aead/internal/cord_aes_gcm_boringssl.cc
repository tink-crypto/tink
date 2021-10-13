// Copyright 2020 Google LLC
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

#include "tink/aead/internal/cord_aes_gcm_boringssl.h"

#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/cord.h"
#include "openssl/aead.h"
#include "openssl/base.h"
#include "openssl/cipher.h"
#include "openssl/err.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::Status CordAesGcmBoringSsl::Init(util::SecretData key_value) {
  util::StatusOr<const EVP_CIPHER*> res =
      internal::GetAesGcmCipherForKeySize(key_value.size());
  if (!res.ok()) {
    return res.status();
  }
  cipher_ = *res;
  key_ = key_value;
  return util::OkStatus();
}

util::StatusOr<std::unique_ptr<CordAead>> CordAesGcmBoringSsl::New(
    util::SecretData key_value) {
  std::unique_ptr<CordAesGcmBoringSsl> aead(new CordAesGcmBoringSsl);
  auto status = aead->Init(key_value);
  if (!status.ok()) {
    return status;
  }
  return util::StatusOr<std::unique_ptr<CordAead>>(std::move(aead));
}

util::StatusOr<absl::Cord> CordAesGcmBoringSsl::Encrypt(
    absl::Cord plaintext, absl::Cord additional_data) const {
  std::string iv = subtle::Random::GetRandomBytes(kIvSizeInBytes);

  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

  if (!EVP_EncryptInit_ex(ctx.get(), cipher_, nullptr, nullptr, nullptr)) {
    return util::Status(util::error::INTERNAL, "Encryption init failed");
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kIvSizeInBytes,
                           nullptr)) {
    return util::Status(util::error::INTERNAL, "Setting IV size failed");
  }

  if (!EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                          reinterpret_cast<const uint8_t*>(key_.data()),
                          reinterpret_cast<const uint8_t*>(iv.data()))) {
    return util::Status(util::error::INTERNAL, "Encryption init failed");
  }

  int len = 0;
  // Process AD
  for (auto ad_chunk : additional_data.Chunks()) {
    if (!EVP_EncryptUpdate(ctx.get(), nullptr, &len,
                           reinterpret_cast<const uint8_t*>(ad_chunk.data()),
                           ad_chunk.size())) {
      return util::Status(util::error::INTERNAL, "Encryption failed");
    }
  }

  char* buffer = std::allocator<char>().allocate(plaintext.size());
  absl::Cord ciphertext_buffer = absl::MakeCordFromExternal(
      absl::string_view(buffer, plaintext.size()), [](absl::string_view sv) {
        std::allocator<char>().deallocate(const_cast<char*>(sv.data()),
                                          sv.size());
      });
  uint64_t ciphertext_buffer_offset = 0;

  for (auto plaintext_chunk : plaintext.Chunks()) {
    if (!EVP_EncryptUpdate(
            ctx.get(),
            reinterpret_cast<uint8_t*>(&(buffer[ciphertext_buffer_offset])),
            &len, reinterpret_cast<const uint8_t*>(plaintext_chunk.data()),
            plaintext_chunk.size())) {
      return util::Status(util::error::INTERNAL, "Encryption failed");
    }
    ciphertext_buffer_offset += plaintext_chunk.size();
  }
  if (!EVP_EncryptFinal_ex(ctx.get(), nullptr, &len)) {
    return util::Status(util::error::INTERNAL, "Encryption failed");
  }

  std::string tag;
  subtle::ResizeStringUninitialized(&tag, kTagSizeInBytes);
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kTagSizeInBytes,
                           reinterpret_cast<uint8_t*>(&tag[0]))) {
    return util::Status(util::error::INTERNAL, "Encryption failed");
  }

  // Create result cord
  absl::Cord result;
  result.Append(iv);
  result.Append(ciphertext_buffer);
  result.Append(tag);
  return result;
}

util::StatusOr<absl::Cord> CordAesGcmBoringSsl::Decrypt(
    absl::Cord ciphertext, absl::Cord additional_data) const {
  if (ciphertext.size() < kIvSizeInBytes + kTagSizeInBytes) {
    return util::Status(util::error::INTERNAL, "Ciphertext too short");
  }

  // First bytes contain IV
  std::string iv = std::string(ciphertext.Subcord(0, kIvSizeInBytes));
  absl::Cord raw_ciphertext = ciphertext.Subcord(
      kIvSizeInBytes, ciphertext.size() - kIvSizeInBytes - kTagSizeInBytes);

  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!EVP_DecryptInit_ex(ctx.get(), cipher_, nullptr, nullptr, nullptr)) {
    return util::Status(util::error::INTERNAL, "Decryption init failed");
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kIvSizeInBytes,
                           nullptr)) {
    return util::Status(util::error::INTERNAL, "Setting IV size failed");
  }

  if (!EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                          reinterpret_cast<const uint8_t*>(key_.data()),
                          reinterpret_cast<const uint8_t*>(iv.data()))) {
    return util::Status(util::error::INTERNAL, "Decryption init failed");
  }

  int len = 0;
  // Process AD
  for (auto ad_chunk : additional_data.Chunks()) {
    if (!EVP_DecryptUpdate(ctx.get(), nullptr, &len,
                           reinterpret_cast<const uint8_t*>(ad_chunk.data()),
                           ad_chunk.size())) {
      return util::Status(util::error::INTERNAL, "Decryption failed");
    }
  }

  uint64_t plaintext_len = ciphertext.size() - kIvSizeInBytes - kTagSizeInBytes;
  char* plaintext_buffer = std::allocator<char>().allocate(plaintext_len);
  uint64_t plaintext_buffer_offset = 0;

  absl::Cord result = absl::MakeCordFromExternal(
      absl::string_view(plaintext_buffer, plaintext_len),
      [](absl::string_view sv) {
        std::allocator<char>().deallocate(const_cast<char*>(sv.data()),
                                          sv.size());
      });

  for (auto ct_chunk : raw_ciphertext.Chunks()) {
    if (!EVP_DecryptUpdate(ctx.get(),
                           reinterpret_cast<uint8_t*>(
                               &plaintext_buffer[plaintext_buffer_offset]),
                           &len,
                           reinterpret_cast<const uint8_t*>(ct_chunk.data()),
                           ct_chunk.size())) {
      return util::Status(util::error::INTERNAL, "Decryption failed");
    }
    plaintext_buffer_offset += ct_chunk.size();
  }

  // Set expected tag value to last chunk in ciphertext Cord
  std::string tag = std::string(
      ciphertext.Subcord(ciphertext.size() - kTagSizeInBytes, kTagSizeInBytes));

  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kTagSizeInBytes,
                           &tag[0])) {
    return util::Status(util::error::INTERNAL,
                        "Could not set authentication tag");
  }
  // Verify authentication tag
  if (!EVP_DecryptFinal_ex(ctx.get(), nullptr, &len)) {
    return util::Status(util::error::INTERNAL, "Authentication failed");
  }
  return result;
}

}  // namespace tink
}  // namespace crypto
