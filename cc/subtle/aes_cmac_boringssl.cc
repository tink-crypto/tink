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
#include "openssl/evp.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// CMAC key sizes in bytes.
// The small key size is used only to check RFC 4493's test vectors due to
// the attack described in
// https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf. We
// check this restriction in AesCmacManager.
static constexpr size_t kSmallKeySize = 16;
static constexpr size_t kBigKeySize = 32;
static constexpr size_t kMaxTagSize = 16;

#ifndef OPENSSL_IS_BORINGSSL
util::StatusOr<const EVP_CIPHER*> CipherForKeySize(size_t key_size) {
  switch (key_size) {
    case 16:
      return EVP_aes_128_cbc();
    case 32:
      return EVP_aes_256_cbc();
  }
  return ToStatusF(util::error::INVALID_ARGUMENT, "Invalid key size %d",
                   key_size);
}
#endif

}  // namespace

// static
util::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(util::SecretData key,
                                                           uint32_t tag_size) {
  auto status = internal::CheckFipsCompatibility<AesCmacBoringSsl>();
  if (!status.ok()) return status;

  if (key.size() != kSmallKeySize && key.size() != kBigKeySize) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid key size: expected %d or %d, found %d",
                     kSmallKeySize, kBigKeySize, key.size());
  }
  if (tag_size > kMaxTagSize) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid tag size: expected lower than %d, found %d",
                     kMaxTagSize, tag_size);
  }
  return {absl::WrapUnique(new AesCmacBoringSsl(std::move(key), tag_size))};
}

util::StatusOr<std::string> AesCmacBoringSsl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  std::string result;
  ResizeStringUninitialized(&result, kMaxTagSize);
#ifdef OPENSSL_IS_BORINGSSL
  const int res =
      AES_CMAC(reinterpret_cast<uint8_t*>(&result[0]), key_.data(), key_.size(),
               reinterpret_cast<const uint8_t*>(data.data()), data.size());
#else
  internal::SslUniquePtr<CMAC_CTX> context(CMAC_CTX_new());
  util::StatusOr<const EVP_CIPHER*> cipher = CipherForKeySize(key_.size());
  if (!cipher.ok()) return cipher.status();
  if (CMAC_Init(context.get(), reinterpret_cast<const uint8_t*>(&key_[0]),
                key_.size(), *cipher, nullptr) <= 0) {
    return util::Status(util::error::INTERNAL, "Failed to compute CMAC");
  }
  if (CMAC_Update(context.get(), reinterpret_cast<const uint8_t*>(data.data()),
                  data.size()) <= 0) {
    return util::Status(util::error::INTERNAL, "Failed to compute CMAC");
  }
  size_t len = 0;
  const int res =
      CMAC_Final(context.get(), reinterpret_cast<uint8_t*>(&result[0]), &len);
#endif
  if (res == 0) {
    return util::Status(util::error::INTERNAL, "Failed to compute CMAC");
  }
  result.resize(tag_size_);
  return result;
}

util::Status AesCmacBoringSsl::VerifyMac(absl::string_view mac,
                                         absl::string_view data) const {
  if (mac.size() != tag_size_) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Incorrect tag size: expected %d, found %d", tag_size_,
                     mac.size());
  }
  util::StatusOr<std::string> computed_mac = ComputeMac(data);
  if (!computed_mac.ok()) return computed_mac.status();
  if (CRYPTO_memcmp(computed_mac->data(), mac.data(), tag_size_) != 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "CMAC verification failed");
  }
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
