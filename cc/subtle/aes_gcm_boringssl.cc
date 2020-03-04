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

#include <string>
#include <vector>

#include "tink/aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "openssl/aead.h"
#include "openssl/err.h"


namespace crypto {
namespace tink {
namespace subtle {

util::Status AesGcmBoringSsl::Init(absl::string_view key_value) {
  const EVP_AEAD* aead =
      SubtleUtilBoringSSL::GetAesGcmAeadForKeySize(key_value.size());
  if (aead == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid key size");
  }
  if (EVP_AEAD_CTX_init(
          ctx_.get(), aead, reinterpret_cast<const uint8_t*>(key_value.data()),
          key_value.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr) != 1) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_AEAD_CTX");
  }
  return util::OkStatus();
}

util::StatusOr<std::unique_ptr<Aead>> AesGcmBoringSsl::New(
    absl::string_view key_value) {
  std::unique_ptr<AesGcmBoringSsl> aead(new AesGcmBoringSsl);
  auto status = aead->Init(key_value);
  if (!status.ok()) {
    return status;
  }
  return util::StatusOr<std::unique_ptr<Aead>>(std::move(aead));
}

util::StatusOr<std::string> AesGcmBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
  std::string result = Random::GetRandomBytes(IV_SIZE_IN_BYTES);
  ResizeStringUninitialized(
      &result, IV_SIZE_IN_BYTES + plaintext.size() + TAG_SIZE_IN_BYTES);
  size_t len;
  if (EVP_AEAD_CTX_seal(
          ctx_.get(), reinterpret_cast<uint8_t*>(&result[IV_SIZE_IN_BYTES]),
          &len, plaintext.size() + TAG_SIZE_IN_BYTES,
          reinterpret_cast<const uint8_t*>(&result[0]), IV_SIZE_IN_BYTES,
          reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
          reinterpret_cast<const uint8_t*>(additional_data.data()),
          additional_data.size()) != 1) {
    return util::Status(util::error::INTERNAL, "Encryption failed");
  }
  return result;
}

util::StatusOr<std::string> AesGcmBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  if (ciphertext.size() < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
    return util::Status(util::error::INVALID_ARGUMENT, "Ciphertext too short");
  }

  std::string result;
  ResizeStringUninitialized(
      &result, ciphertext.size() - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES);
  size_t len;
  if (EVP_AEAD_CTX_open(
          ctx_.get(), reinterpret_cast<uint8_t*>(&result[0]), &len,
          result.size(),
          // The nonce is the first |IV_SIZE_IN_BYTES| bytes of |ciphertext|.
          reinterpret_cast<const uint8_t*>(ciphertext.data()), IV_SIZE_IN_BYTES,
          // The input is the remainder.
          reinterpret_cast<const uint8_t*>(ciphertext.data()) +
              IV_SIZE_IN_BYTES,
          ciphertext.size() - IV_SIZE_IN_BYTES,
          reinterpret_cast<const uint8_t*>(additional_data.data()),
          additional_data.size()) != 1) {
    return util::Status(util::error::INTERNAL, "Authentication failed");
  }
  return result;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
