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

#include "openssl/cmac.h"
#include "openssl/err.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(
    const std::string& key_value, uint32_t tag_size) {
  if (key_value.size() != kSmallKeySize && key_value.size() != kBigKeySize) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }
  if (tag_size > kMaxTagSize) {
    return util::Status(util::error::INTERNAL, "invalid tag size");
  }
  std::unique_ptr<Mac> cmac(new AesCmacBoringSsl(key_value, tag_size));
  return std::move(cmac);
}

AesCmacBoringSsl::AesCmacBoringSsl(const std::string& key_value,
                                   uint32_t tag_size)
    : key_value_(key_value), tag_size_(tag_size) {}

util::StatusOr<std::string> AesCmacBoringSsl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  uint8_t buf[kMaxTagSize];
  const int res =
      AES_CMAC(buf, reinterpret_cast<const uint8_t*>(key_value_.data()),
               key_value_.size(), reinterpret_cast<const uint8_t*>(data.data()),
               data.size());
  if (res == 0) {
    return util::Status(util::error::INTERNAL,
                        "BoringSSL failed to compute CMAC");
  }
  return std::string(reinterpret_cast<char*>(buf), tag_size_);
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
      AES_CMAC(buf, reinterpret_cast<const uint8_t*>(key_value_.data()),
               key_value_.size(), reinterpret_cast<const uint8_t*>(data.data()),
               data.size());
  if (res == 0) {
    return util::Status(util::error::INTERNAL,
                        "BoringSSL failed to compute CMAC");
  }
  uint8_t diff = 0;
  for (uint32_t i = 0; i < tag_size_; i++) {
    diff |= buf[i] ^ static_cast<uint8_t>(mac[i]);
  }
  if (diff == 0) {
    return util::Status::OK;
  } else {
    return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
