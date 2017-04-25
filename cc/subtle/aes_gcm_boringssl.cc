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

#include "cc/subtle/aes_gcm_boringssl.h"

#include <string>
#include <vector>

#include "cc/aead.h"
#include "cc/subtle/random.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "openssl/err.h"
#include "openssl/evp.h"

using google::cloud::crypto::tink::HashType;

namespace cloud {
namespace crypto {
namespace tink {

static const EVP_CIPHER* GetCipherForKeySize(int size_in_bytes) {
  switch (size_in_bytes) {
    case 16 : return EVP_aes_128_gcm();
    case 24 : return EVP_aes_192_gcm();
    case 32 : return EVP_aes_256_gcm();
    default : return nullptr;
  }
}

AesGcmBoringSsl::AesGcmBoringSsl(
    const std::string& key_value, const EVP_CIPHER *cipher)
    : key_(key_value), cipher_(cipher) {}

util::StatusOr<std::unique_ptr<Aead>>
AesGcmBoringSsl::New(const std::string& key_value) {
  const EVP_CIPHER* cipher = GetCipherForKeySize(key_value.size());
  if (cipher == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }
  std::unique_ptr<Aead> aead(new AesGcmBoringSsl(key_value, cipher));
  return std::move(aead);
}

util::StatusOr<std::string> AesGcmBoringSsl::Encrypt(
    const google::protobuf::StringPiece& plaintext,
    const google::protobuf::StringPiece& additional_data) const {
 
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }
  int ret = EVP_EncryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                               nullptr /* key */, nullptr /* IV */);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "EVP_EncryptInit_ex failed");
  }
  ret =
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_IN_BYTES,
                          nullptr);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "IV length not supported");
  }
  const std::string iv = Random::GetRandomBytes(IV_SIZE_IN_BYTES);
  ret = EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           reinterpret_cast<const uint8_t *>(key_.data()),
                           reinterpret_cast<const uint8_t *>(iv.data()));
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "Could not initialize ctx");
  }
  int len;
  ret = EVP_EncryptUpdate(
      ctx.get(), nullptr, &len,
      reinterpret_cast<const uint8_t *>(additional_data.data()),
      additional_data.size());
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "AAD is not supported");
  }
  size_t ciphertext_size = iv.size() + plaintext.size() +
      TAG_SIZE_IN_BYTES;
  // TODO(bleichen): Check if it is OK to work on a string.
  //   This is unclear since some compiler may use copy-on-write.
  std::vector<uint8_t> ct(ciphertext_size);
  memcpy(&ct[0], reinterpret_cast<const uint8_t *>(iv.data()), iv.size());
  size_t written = iv.size();
  ret = EVP_EncryptUpdate(ctx.get(),
                          &ct[written], &len,
                          reinterpret_cast<const uint8_t *>(plaintext.data()),
                          plaintext.size());
  if (ret != 1) {
    util::Status(util::error::INTERNAL, "Encryption failed");
  }
  written += len;
  ret = EVP_EncryptFinal_ex(ctx.get(), &ct[written], &len);
  written += len;
  if (ret != 1) {
    util::Status(util::error::INTERNAL, "EVP_EncryptFinal_ex failed");
  }
  ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE_IN_BYTES,
                            &ct[written]);
  if (ret != 1) {
    util::Status(util::error::INTERNAL, "Could not compute tag");
  }
  written += TAG_SIZE_IN_BYTES;
  if (written != ciphertext_size) {
    util::Status(util::error::INTERNAL, "Incorrect ciphertext size");
  }
  return std::string(reinterpret_cast<const char*>(&ct[0]), written);
}

util::StatusOr<std::string> AesGcmBoringSsl::Decrypt(
    const google::protobuf::StringPiece& ciphertext,
    const google::protobuf::StringPiece& additional_data) const {
  if (ciphertext.size() < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
    return util::Status(util::error::INTERNAL, "Ciphertext too short");
  }

  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }
  // Set the cipher.
  int ret = EVP_DecryptInit_ex(ctx.get(), cipher_, nullptr, nullptr, nullptr);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "EVP_DecryptInit_ex failed");
  }
  // Set IV and tag length.
  ret =
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_IN_BYTES,
                          nullptr);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "IV length not supported");
  }

  // Initialise key and IV
  ret = EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           reinterpret_cast<const uint8_t*>(key_.data()),
                           reinterpret_cast<const uint8_t*>(ciphertext.data()));
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "Could not initialize key");
  }

  int len;
  ret = EVP_DecryptUpdate(
      ctx.get(), nullptr, &len,
      reinterpret_cast<const uint8_t *>(additional_data.data()),
      additional_data.size());
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "AAD is not supported");
  }
  size_t plaintext_size = ciphertext.size() - IV_SIZE_IN_BYTES -
      TAG_SIZE_IN_BYTES;
  std::vector<uint8_t> pt(plaintext_size);
  size_t read = IV_SIZE_IN_BYTES;
  size_t written = 0;
  ret = EVP_DecryptUpdate(
      ctx.get(), &pt[written], &len,
      reinterpret_cast<const uint8_t *>(&ciphertext.data()[read]),
      plaintext_size);
  if (ret != 1) {
    util::Status(util::error::INTERNAL, "Decryption failed");
  }
  written += len;

  // Copy the tag since EVP_CIPHER_CTX_ctrl does not accept const pointers.
  uint8_t tag[TAG_SIZE_IN_BYTES];
  memcpy(tag, &ciphertext.data()[ciphertext.size() - TAG_SIZE_IN_BYTES],
         TAG_SIZE_IN_BYTES);
  ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            TAG_SIZE_IN_BYTES, tag);
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "Could not set tag");
  }

  ret = EVP_DecryptFinal_ex(ctx.get(), &pt[written], &len);
  written += len;
  if (ret != 1) {
    return util::Status(util::error::INTERNAL, "Authentication failed");
  }
  if (written != plaintext_size) {
    return util::Status(util::error::INTERNAL, "Incorrect plaintext size");
  }
  return std::string(reinterpret_cast<const char*>(&pt[0]), written);
}

}  // namespace tink
}  // namespace crypto
}  // namespace cloud
