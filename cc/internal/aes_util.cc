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
#include "tink/internal/util.h"
#include "tink/util/status.h"
#if !defined(OPENSSL_IS_BORINGSSL)
#include "openssl/modes.h"
#endif
#include "tink/util/secret_data.h"

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

}  // namespace internal
}  // namespace tink
}  // namespace crypto
