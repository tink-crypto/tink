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

#include "tink/subtle/hmac_boringssl.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/digest.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/mem.h"
#include "tink/internal/md_util.h"
#include "tink/internal/util.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<Mac>> HmacBoringSsl::New(HashType hash_type,
                                                        uint32_t tag_size,
                                                        util::SecretData key) {
  auto status = internal::CheckFipsCompatibility<HmacBoringSsl>();
  if (!status.ok()) return status;

  util::StatusOr<const EVP_MD*> md = internal::EvpHashFromHashType(hash_type);
  if (!md.ok()) {
    return md.status();
  }
  if (EVP_MD_size(*md) < tag_size) {
    // The key manager is responsible to security policies.
    // The checks here just ensure the preconditions of the primitive.
    // If this fails then something is wrong with the key manager.
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid tag size");
  }
  if (key.size() < kMinKeySize) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid key size");
  }
  return {absl::WrapUnique(new HmacBoringSsl(*md, tag_size, std::move(key)))};
}

util::StatusOr<std::string> HmacBoringSsl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int out_len;
  const uint8_t* res = HMAC(md_, key_.data(), key_.size(),
                            reinterpret_cast<const uint8_t*>(data.data()),
                            data.size(), buf, &out_len);
  if (res == nullptr) {
    // TODO(bleichen): We expect that BoringSSL supports the
    //   hashes that we use. Maybe we should have a status that indicates
    //   such mismatches between expected and actual behaviour.
    return util::Status(absl::StatusCode::kInternal,
                        "BoringSSL failed to compute HMAC");
  }
  return std::string(reinterpret_cast<char*>(buf), tag_size_);
}

util::Status HmacBoringSsl::VerifyMac(absl::string_view mac,
                                      absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  if (mac.size() != tag_size_) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "incorrect tag size");
  }
  uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int out_len;
  const uint8_t* res = HMAC(md_, key_.data(), key_.size(),
                            reinterpret_cast<const uint8_t*>(data.data()),
                            data.size(), buf, &out_len);
  if (res == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "BoringSSL failed to compute HMAC");
  }
  if (CRYPTO_memcmp(buf, mac.data(), tag_size_) != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "verification failed");
  }
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
