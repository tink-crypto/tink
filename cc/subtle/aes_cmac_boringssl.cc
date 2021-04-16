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

#include "tink/subtle/aes_cmac_boringssl.h"

#include <string>

#include "absl/memory/memory.h"
#include "openssl/cmac.h"
#include "openssl/mem.h"
#include "tink/subtle/subtle_util.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(util::SecretData key,
                                                           uint32_t tag_size) {
  auto status = internal::CheckFipsCompatibility<AesCmacBoringSsl>();
  if (!status.ok()) return status;

  if (key.size() != kSmallKeySize && key.size() != kBigKeySize) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid key size");
  }
  if (tag_size > kMaxTagSize) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid tag size");
  }
  return {absl::WrapUnique(new AesCmacBoringSsl(std::move(key), tag_size))};
}

util::StatusOr<std::string> AesCmacBoringSsl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  std::string result;
  ResizeStringUninitialized(&result, kMaxTagSize);
  const int res =
      AES_CMAC(reinterpret_cast<uint8_t*>(&result[0]), key_.data(), key_.size(),
               reinterpret_cast<const uint8_t*>(data.data()), data.size());
  if (res == 0) {
    return util::Status(util::error::INTERNAL,
                        "BoringSSL failed to compute CMAC");
  }
  result.resize(tag_size_);
  return result;
}

util::Status AesCmacBoringSsl::VerifyMac(absl::string_view mac,
                                         absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  if (mac.size() != tag_size_) {
    return util::Status(util::error::INVALID_ARGUMENT, "incorrect tag size");
  }
  uint8_t buf[kMaxTagSize];
  const int res =
      AES_CMAC(buf, key_.data(), key_.size(),
               reinterpret_cast<const uint8_t*>(data.data()), data.size());
  if (res == 0) {
    return util::Status(util::error::INTERNAL,
                        "BoringSSL failed to compute CMAC");
  }
  if (CRYPTO_memcmp(buf, mac.data(), tag_size_) != 0) {
    return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
  }
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
