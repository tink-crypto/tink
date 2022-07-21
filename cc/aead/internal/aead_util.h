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
#ifndef TINK_AEAD_INTERNAL_AEAD_UTIL_H_
#define TINK_AEAD_INTERNAL_AEAD_UTIL_H_

#include "openssl/evp.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns a pointer to an AES-GCM EVP_CIPHER for the given key size.
util::StatusOr<const EVP_CIPHER *> GetAesGcmCipherForKeySize(
    uint32_t key_size_in_bytes);

#ifdef OPENSSL_IS_BORINGSSL
// Returns a pointer to an AES-GCM EVP_AEAD for the given key size.
util::StatusOr<const EVP_AEAD *> GetAesGcmAeadForKeySize(
    uint32_t key_size_in_bytes);

// Returns a pointer to an AES-GCM-SIV EVP_AEAD for `key_size_in_bytes` or an
// error if `key_size_in_bytes` is invalid.
util::StatusOr<const EVP_AEAD *> GetAesGcmSivAeadCipherForKeySize(
    int key_size_in_bytes);
#endif

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AEAD_UTIL_H_
