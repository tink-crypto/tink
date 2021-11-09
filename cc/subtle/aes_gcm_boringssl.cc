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

#include "tink/subtle/aes_gcm_boringssl.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/evp.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

// We follow different code paths at compile time depending on whether this is
// linked against OpenSSL or BoringSSL. A different path for OpenSSL is needed
// because the EVP_AEAD interface is defined only in BoringSSL; nevertheless, we
// want to keep using EVP_AEAD when possible.
#ifndef OPENSSL_IS_BORINGSSL

util::Status SetIv(EVP_CIPHER_CTX* context, absl::string_view iv,
                   bool encryption) {
  const int encryption_flag = encryption ? 1 : 0;
  // Set the IV.
  if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(),
                          /*ptr=*/nullptr) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Setting IV size failed");
  }
  if (EVP_CipherInit_ex(context, /*cipher=*/nullptr, /*impl=*/nullptr,
                        /*key=*/nullptr,
                        reinterpret_cast<const uint8_t*>(&iv[0]),
                        /*enc=*/encryption_flag) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Failed to set the IV");
  }

  return util::OkStatus();
}

#endif

}  // namespace

util::StatusOr<std::unique_ptr<Aead>> AesGcmBoringSsl::New(
    const util::SecretData& key) {
  auto status = internal::CheckFipsCompatibility<AesGcmBoringSsl>();
  if (!status.ok()) return status;

#ifdef OPENSSL_IS_BORINGSSL
  util::StatusOr<const EVP_AEAD*> aead =
      internal::GetAesGcmAeadForKeySize(key.size());
#else
  util::StatusOr<const EVP_CIPHER*> aead =
      internal::GetAesGcmCipherForKeySize(key.size());
#endif
  if (!aead.ok()) {
    return aead.status();
  }

#ifdef OPENSSL_IS_BORINGSSL
  internal::SslUniquePtr<EVP_AEAD_CTX> context(EVP_AEAD_CTX_new(
      *aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH));
#else
  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
#endif
  if (context == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX initialization Failed");
  }

#ifndef OPENSSL_IS_BORINGSSL
  // Initialize the context for the cipher having OpenSSL to make some
  // precomputations on the key. It doesn't matter at this point if we set
  // encryption or decryption, it will be overwritten later on anyways any time
  // we call EVP_CipherInit_ex.
  if (EVP_CipherInit_ex(context.get(), *aead, /*impl=*/nullptr,
                        reinterpret_cast<const uint8_t*>(&key[0]),
                        /*iv=*/nullptr, /*enc=*/1) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Context initialization failed");
  }
#endif

  std::unique_ptr<Aead> aes_aead =
      absl::WrapUnique(new AesGcmBoringSsl(std::move(context)));
  return aes_aead;
}

util::StatusOr<std::string> AesGcmBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
#ifdef OPENSSL_IS_BORINGSSL
  std::string result = Random::GetRandomBytes(kIvSizeInBytes);
  // The result of this operation is going to be a buffer:
  // | iv | ciphertext | tag |.
  ResizeStringUninitialized(
      &result, kIvSizeInBytes + plaintext.size() + kTagSizeInBytes);

  size_t ciphertext_length;
  uint8_t* iv = reinterpret_cast<uint8_t*>(&result[0]);
  uint8_t* ciphertext = reinterpret_cast<uint8_t*>(&result[0] + kIvSizeInBytes);
  const size_t max_out_length = plaintext.size() + kTagSizeInBytes;

  if (EVP_AEAD_CTX_seal(
          context_.get(), ciphertext, &ciphertext_length, max_out_length, iv,
          kIvSizeInBytes, reinterpret_cast<const uint8_t*>(plaintext.data()),
          plaintext.size(),
          reinterpret_cast<const uint8_t*>(additional_data.data()),
          additional_data.size()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Encryption failed");
  }
  return result;
#else
  absl::string_view plaintext_data = internal::EnsureStringNonNull(plaintext);
  absl::string_view aad = internal::EnsureStringNonNull(additional_data);

  std::string result = Random::GetRandomBytes(kIvSizeInBytes);
  ResizeStringUninitialized(
      &result, kIvSizeInBytes + plaintext_data.size() + kTagSizeInBytes);

  // For thread safety we copy the context and only then set the IV. This
  // allows to allocate an AesGcmBoringSsl cipher, and intialize the context
  // to force precomputation on the key, and only then set a different IV for
  // each call to `Encrypt`.
  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
  // This makes a copy of the `cipher_data` field of the context too, which
  // contains the key material and IV (see
  // https://github.com/google/boringssl/blob/master/crypto/fipsmodule/cipher/cipher.c#L116).
  EVP_CIPHER_CTX_copy(context.get(), context_.get());

  auto iv = absl::string_view(result.data(), kIvSizeInBytes);
  util::Status res = SetIv(context.get(), iv, /*encryption=*/true);
  if (!res.ok()) return res;

  // Set the additional auth. data.
  int len = 0;
  if (EVP_EncryptUpdate(context.get(), nullptr, &len,
                        reinterpret_cast<const uint8_t*>(aad.data()),
                        aad.size()) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Failed to add AAD");
  }

  // Write the ciphertext after the iv.
  auto* ciphertext = reinterpret_cast<uint8_t*>(&result[0] + kIvSizeInBytes);
  // Encrypt and finalize.
  if (EVP_EncryptUpdate(context.get(), ciphertext, &len,
                        reinterpret_cast<const uint8_t*>(plaintext_data.data()),
                        plaintext_data.size()) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Encryption failed");
  }
  if (EVP_EncryptFinal_ex(context.get(), /*out=*/nullptr, &len) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Finalization failed");
  }

  // Write the tag after the ciphertext.
  const int tag_offset = kIvSizeInBytes + plaintext_data.size();
  auto* tag_data = reinterpret_cast<uint8_t*>(&result[0] + tag_offset);
  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, kTagSizeInBytes,
                          tag_data) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Failed to get the tag");
  }
  return result;
#endif
}

util::StatusOr<std::string> AesGcmBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  if (ciphertext.size() < kIvSizeInBytes + kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext too short");
  }
#ifdef OPENSSL_IS_BORINGSSL
  std::string result;
  ResizeStringUninitialized(
      &result, ciphertext.size() - kIvSizeInBytes - kTagSizeInBytes);
  size_t plaintext_len;
  uint8_t* plaintext_data = reinterpret_cast<uint8_t*>(&result[0]);
  const uint8_t* nonce = reinterpret_cast<const uint8_t*>(ciphertext.data());
  const uint8_t* ciphertex_and_tag =
      reinterpret_cast<const uint8_t*>(ciphertext.data() + kIvSizeInBytes);

  if (EVP_AEAD_CTX_open(
          context_.get(), plaintext_data, &plaintext_len, result.size(),
          // The nonce is the first |kIvSizeInBytes| bytes of |ciphertext|.
          nonce, kIvSizeInBytes,
          // The input is the remainder.
          ciphertex_and_tag, ciphertext.size() - kIvSizeInBytes,
          reinterpret_cast<const uint8_t*>(additional_data.data()),
          additional_data.size()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Authentication failed");
  }
  return result;
#else
  absl::string_view aad = internal::EnsureStringNonNull(additional_data);

  const size_t plaintext_size =
      ciphertext.size() - kIvSizeInBytes - kTagSizeInBytes;
  // "Unpack" the input into IV, ciphertext and Tag
  auto iv = absl::string_view(ciphertext.data(), kIvSizeInBytes);
  const int ciphertex_offset = kIvSizeInBytes;
  const int tag_offset = ciphertex_offset + plaintext_size;
  absl::Span<const uint8_t> ciphertext_only = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(ciphertext.data() + ciphertex_offset),
      plaintext_size);

  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
  EVP_CIPHER_CTX_copy(context.get(), context_.get());

  util::Status res = SetIv(context.get(), iv, /*encryption=*/false);
  if (!res.ok()) return res;

  int len = 0;
  // Add additional auth. data.
  if (EVP_DecryptUpdate(context.get(), /*out=*/nullptr, &len,
                        reinterpret_cast<const uint8_t*>(aad.data()),
                        aad.size()) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Decryption failed");
  }

  // This copy is needed since EVP_CIPHER_CTX_ctrl requires a non-const pointer
  // even if the EVP_CTRL_GCM_SET_TAG operation doesn't modify the content of
  // the buffer.
  auto tag = std::string(&ciphertext[tag_offset], kTagSizeInBytes);

  // Set the tag.
  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, kTagSizeInBytes,
                          reinterpret_cast<uint8_t*>(&tag[0])) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Could not set authentication tag");
  }
  std::string result;

  ResizeStringUninitialized(&result, plaintext_size);
  // Decrypt and Verify the Tag.
  if (!EVP_DecryptUpdate(context.get(), reinterpret_cast<uint8_t*>(&result[0]),
                         &len, ciphertext_only.data(),
                         ciphertext_only.size())) {
    return util::Status(absl::StatusCode::kInternal, "Decryption failed");
  }
  if (!EVP_DecryptFinal_ex(context.get(), nullptr, &len)) {
    return util::Status(absl::StatusCode::kInternal, "Authentication failed");
  }

  return result;
#endif
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
