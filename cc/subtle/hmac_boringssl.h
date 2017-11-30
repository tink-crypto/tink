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

#ifndef TINK_SUBTLE_HMAC_BORINGSSL_H_
#define TINK_SUBTLE_HMAC_BORINGSSL_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "cc/mac.h"
#include "cc/subtle/common_enums.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "openssl/evp.h"

namespace crypto {
namespace tink {
namespace subtle {

class HmacBoringSsl : public Mac {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<Mac>> New(
      HashType hash_type,
      uint32_t tag_size, const std::string& key_value);

  // Computes and returns the HMAC for 'data'.
  crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const override;

  // Verifies if 'mac' is a correct HMAC for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  crypto::tink::util::Status VerifyMac(
      absl::string_view mac,
      absl::string_view data) const override;

  virtual ~HmacBoringSsl() {}

 private:
  HmacBoringSsl() {}
  HmacBoringSsl(const EVP_MD* md, uint32_t tag_size,
                const std::string& key_value);

  // HmacBoringSsl is not owner of md (it is owned by BoringSSL).
  const EVP_MD* md_;
  uint32_t tag_size_;
  std::string key_value_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_HMAC_BORINGSSL_H_
