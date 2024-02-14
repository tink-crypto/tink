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
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

// Set the IV `iv` for the given `context`. if `encryption` is true, set the
// context for encryption, and for decryption otherwise.
util::Status SetIvAndDirection(EVP_CIPHER_CTX* context, absl::string_view iv,
                               bool encryption) {
  const int encryption_flag = encryption ? 1 : 0;
  // Set the IV size.
  if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(),
                          /*ptr=*/nullptr) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to set the IV size");
  }
  // Finally set the IV bytes.
  if (EVP_CipherInit_ex(context, /*cipher=*/nullptr, /*engine=*/nullptr,
                        /*key=*/nullptr,
                        reinterpret_cast<const uint8_t*>(&iv[0]),
                        /*enc=*/encryption_flag) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "Failed to set the IV");
  }

  return util::OkStatus();
}

#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
// Returns a new EVP_CIPHER_CTX for encryption (`encryption` == true) or
// decryption (`encryption` == false). It tries to skip part of the
// initialization copying `partial_context`.
util::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> NewContextFromPartial(
    EVP_CIPHER_CTX* partial_context, absl::string_view iv, bool encryption) {
  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
  if (context == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX_new failed");
  }
  // Try making a copy of `partial_context` to skip some pre-computations.
  //
  // NOTE: With BoringSSL and OpenSSL 1.1.1 EVP_CIPHER_CTX_copy makes a copy
  // of the `cipher_data` field of `context` as well, which contains the key
  // material and IV (see [1] and [2]).
  //
  // [1]https://github.com/google/boringssl/blob/4c8bcf0da2951cacd8ed8eaa7fd2df4b22fca23b/crypto/fipsmodule/cipher/cipher.c#L116
  // [2]https://github.com/openssl/openssl/blob/830bf8e1e4749ad65c51b6a1d0d769ae689404ba/crypto/evp/evp_enc.c#L703
  if (EVP_CIPHER_CTX_copy(context.get(), partial_context) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX_copy failed");
  }
  util::Status res =
      SetIvAndDirection(context.get(), iv, /*encryption=*/encryption);
  if (!res.ok()) {
    return res;
  }
  return std::move(context);
}
#else
// Returns a new EVP_CIPHER_CTX for encryption (`encryption` == true) or
// decryption (`encryption` == false) with given `key` and `iv`.
//
// NOTE: Copying the context fails with OpenSSL 3.0, which doesn't provide a
// `dupctx` function for aead ciphers (see [1], [2]).
//
// [1]https://github.com/openssl/openssl/blob/eb52450f5151e8e78743ab05de21a344823316f5/crypto/evp/evp_enc.c#L1427
// [2]https://github.com/openssl/openssl/blob/cac250755efd0c40cc6127a0e4baceb8d226c7e3/providers/implementations/include/prov/ciphercommon_aead.h#L30
util::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> NewContext(
    const util::SecretData& key, absl::string_view iv, bool encryption) {
  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
  if (context == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX_new failed");
  }
  util::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesGcmCipherForKeySize(key.size());
  if (!cipher.ok()) {
    return cipher.status();
  }
  if (EVP_CipherInit_ex(context.get(), *cipher, /*impl=*/nullptr,
                        reinterpret_cast<const uint8_t*>(key.data()),
                        /*iv=*/nullptr, /*enc=*/1) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Context initialization failed");
  }
  util::Status res =
      SetIvAndDirection(context.get(), iv, /*encryption=*/encryption);
  if (!res.ok()) {
    return res;
  }
  return std::move(context);
}
#endif

}  // namespace

util::StatusOr<std::unique_ptr<CordAead>> CordAesGcmBoringSsl::New(
    const util::SecretData& key_value) {
  util::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesGcmCipherForKeySize(key_value.size());
  if (!cipher.ok()) {
    return cipher.status();
  }

  internal::SslUniquePtr<EVP_CIPHER_CTX> partial_context(EVP_CIPHER_CTX_new());
  // Initialize a partial context for the cipher to allow OpenSSL/BoringSSL
  // making some precomputations on the key. Encrypt and Decrypt will try making
  // a copy of this context to avoid doing the same initializations again and to
  // guarantee thread safety.
  //
  // NOTE: It doesn't matter at this point if we set the direction to encryption
  // or decryption, it will be overwritten later any time we call
  // EVP_CipherInit_ex.
  if (EVP_CipherInit_ex(partial_context.get(), *cipher, /*engine=*/nullptr,
                        reinterpret_cast<const uint8_t*>(&key_value[0]),
                        /*iv=*/nullptr, /*enc=*/1) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Context initialization failed");
  }

  std::unique_ptr<CordAead> aead = absl::WrapUnique(
      new CordAesGcmBoringSsl(std::move(partial_context), key_value));
  return std::move(aead);
}

util::StatusOr<absl::Cord> CordAesGcmBoringSsl::Encrypt(
    absl::Cord plaintext, absl::Cord associated_data) const {
  std::string iv = subtle::Random::GetRandomBytes(kIvSizeInBytes);

#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
  util::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContextFromPartial(partial_context_.get(), iv, /*encryption=*/true);
#else
  util::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContext(key_, iv, /*encryption=*/true);
#endif
  if (!context.ok()) {
    return context.status();
  }

  int len = 0;
  // Process AAD.
  for (auto ad_chunk : associated_data.Chunks()) {
    if (!EVP_EncryptUpdate(context->get(), /*out=*/nullptr, &len,
                           reinterpret_cast<const uint8_t*>(ad_chunk.data()),
                           ad_chunk.size())) {
      return util::Status(absl::StatusCode::kInternal, "Encryption failed");
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
            context->get(),
            reinterpret_cast<uint8_t*>(&(buffer[ciphertext_buffer_offset])),
            &len, reinterpret_cast<const uint8_t*>(plaintext_chunk.data()),
            plaintext_chunk.size())) {
      return util::Status(absl::StatusCode::kInternal, "Encryption failed");
    }
    ciphertext_buffer_offset += plaintext_chunk.size();
  }
  if (!EVP_EncryptFinal_ex(context->get(), nullptr, &len)) {
    return util::Status(absl::StatusCode::kInternal, "Encryption failed");
  }

  std::string tag;
  subtle::ResizeStringUninitialized(&tag, kTagSizeInBytes);
  if (!EVP_CIPHER_CTX_ctrl(context->get(), EVP_CTRL_GCM_GET_TAG,
                           kTagSizeInBytes,
                           reinterpret_cast<uint8_t*>(&tag[0]))) {
    return util::Status(absl::StatusCode::kInternal, "Encryption failed");
  }

  // Create result cord
  absl::Cord result;
  result.Append(iv);
  result.Append(ciphertext_buffer);
  result.Append(tag);
  return result;
}

util::StatusOr<absl::Cord> CordAesGcmBoringSsl::Decrypt(
    absl::Cord ciphertext, absl::Cord associated_data) const {
  if (ciphertext.size() < kIvSizeInBytes + kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInternal, "Ciphertext too short");
  }

  // First bytes contain the IV.
  std::string iv = std::string(ciphertext.Subcord(0, kIvSizeInBytes));
  absl::Cord raw_ciphertext = ciphertext.Subcord(
      kIvSizeInBytes, ciphertext.size() - kIvSizeInBytes - kTagSizeInBytes);

#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
  util::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContextFromPartial(partial_context_.get(), iv, /*encryption=*/false);
#else
  util::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContext(key_, iv, /*encryption=*/false);
#endif
  if (!context.ok()) {
    return context.status();
  }

  int len = 0;
  // Process associated data.
  for (auto ad_chunk : associated_data.Chunks()) {
    if (!EVP_DecryptUpdate(context->get(), /*out=*/nullptr, &len,
                           reinterpret_cast<const uint8_t*>(ad_chunk.data()),
                           ad_chunk.size())) {
      return util::Status(absl::StatusCode::kInternal, "Decryption failed");
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
    if (!EVP_DecryptUpdate(context->get(),
                           reinterpret_cast<uint8_t*>(
                               &plaintext_buffer[plaintext_buffer_offset]),
                           &len,
                           reinterpret_cast<const uint8_t*>(ct_chunk.data()),
                           ct_chunk.size())) {
      return util::Status(absl::StatusCode::kInternal, "Decryption failed");
    }
    plaintext_buffer_offset += ct_chunk.size();
  }

  // Set expected tag value to last chunk in ciphertext Cord.
  std::string tag = std::string(
      ciphertext.Subcord(ciphertext.size() - kTagSizeInBytes, kTagSizeInBytes));

  if (!EVP_CIPHER_CTX_ctrl(context->get(), EVP_CTRL_GCM_SET_TAG,
                           kTagSizeInBytes, &tag[0])) {
    return util::Status(absl::StatusCode::kInternal,
                        "Could not set authentication tag");
  }
  // Verify authentication tag.
  if (!EVP_DecryptFinal_ex(context->get(), nullptr, &len)) {
    return util::Status(absl::StatusCode::kInternal, "Authentication failed");
  }
  return result;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
