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
#ifndef TINK_INTERNAL_AES_UTIL_H_
#define TINK_INTERNAL_AES_UTIL_H_

#include <cstdint>
#include <memory>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// AES block size in bytes.
constexpr int AesBlockSize() { return 16; }

// Wrapper for BoringSSL/OpenSSL low-level functions that encrypt/decrypt (same
// operation in CTR mode) `data`, with IV `iv` and key `key`. The result is
// written to `out`. `out` may fully overlap with `data`; partial overlaps will
// result in an kInvalidArgument error. `iv` is incremented of the number of
// blocks that were encrypted/decrypted.
crypto::tink::util::Status AesCtr128Crypt(absl::string_view data,
                                          uint8_t iv[AesBlockSize()],
                                          const AES_KEY* key,
                                          absl::Span<char> out);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_AES_UTIL_H_
