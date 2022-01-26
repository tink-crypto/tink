// Copyright 2021 Google LLC
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
#include "tink/aead/internal/aead_util.h"

#include "absl/status/status.h"
#include "openssl/evp.h"
#include "tink/util/errors.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<const EVP_CIPHER *> GetAesGcmCipherForKeySize(
    uint32_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aes_128_gcm();
    case 32:
      return EVP_aes_256_gcm();
    default:
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Invalid key size %d", key_size_in_bytes);
  }
}

#ifdef OPENSSL_IS_BORINGSSL
util::StatusOr<const EVP_AEAD *> GetAesGcmAeadForKeySize(
    uint32_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aead_aes_128_gcm();
    case 32:
      return EVP_aead_aes_256_gcm();
    default:
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Invalid key size %d", key_size_in_bytes);
  }
}

util::StatusOr<const EVP_AEAD *> GetAesGcmSivAeadCipherForKeySize(
    int key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aead_aes_128_gcm_siv();
    case 32:
      return EVP_aead_aes_256_gcm_siv();
    default:
      return ToStatusF(
          absl::StatusCode::kInvalidArgument,
          "Invalid key size; valid values are {16, 32} bytes, got %d",
          key_size_in_bytes);
  }
}
#endif

}  // namespace internal
}  // namespace tink
}  // namespace crypto
