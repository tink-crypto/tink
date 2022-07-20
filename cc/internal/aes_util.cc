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
#include "tink/internal/aes_util.h"

#include <cstdint>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#ifndef OPENSSL_IS_BORINGSSL
// This is needed to use block128_f, which is necessary when OpenSSL is used.
#include "openssl/modes.h"
#endif
#include "tink/internal/util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AesCtr128Crypt(absl::string_view data, uint8_t iv[AesBlockSize()],
                            const AES_KEY* key, absl::Span<char> out) {
  if (out.size() < data.size()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid size for output buffer; expected at least ",
                     data.size(), " got ", out.size()));
  }

  // Only full overlap or no overlap is allowed.
  if (!BuffersAreIdentical(data, absl::string_view(out.data(), out.size())) &&
      BuffersOverlap(data, absl::string_view(out.data(), out.size()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Buffers must not partially overlap");
  }

  unsigned int num = 0;
  std::vector<uint8_t> ecount_buf(AesBlockSize(), 0);
  // OpenSSL >= v1.1.0 public APIs no longer exposes an AES_ctr128_encrypt
  // function; as an alternative we use CRYPTO_ctr128_encrypt when OpenSSL is
  // used as a backend. The latter is not part of the public API of BoringSSL,
  // so we must selectively compile using either of them.
#ifdef OPENSSL_IS_BORINGSSL
  AES_ctr128_encrypt(reinterpret_cast<const uint8_t*>(data.data()),
                     reinterpret_cast<uint8_t*>(out.data()), data.size(), key,
                     iv, ecount_buf.data(), &num);
#else
  CRYPTO_ctr128_encrypt(reinterpret_cast<const uint8_t*>(data.data()),
                        reinterpret_cast<uint8_t*>(out.data()), data.size(),
                        key, iv, ecount_buf.data(), &num,
                        reinterpret_cast<block128_f>(AES_encrypt));
#endif
  return util::OkStatus();
}

util::StatusOr<const EVP_CIPHER*> GetAesCtrCipherForKeySize(
    uint32_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aes_128_ctr();
    case 32:
      return EVP_aes_256_ctr();
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid key size ", key_size_in_bytes));
  }
}

util::StatusOr<const EVP_CIPHER*> GetAesCbcCipherForKeySize(
    uint32_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aes_128_cbc();
    case 32:
      return EVP_aes_256_cbc();
  }
  return util::Status(absl::StatusCode::kInvalidArgument,
                      absl::StrCat("Invalid key size ", key_size_in_bytes));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
