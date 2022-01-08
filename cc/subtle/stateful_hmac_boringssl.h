// Copyright 2020 Google LLC
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

#ifndef TINK_SUBTLE_STATEFUL_HMAC_BORINGSSL_H_
#define TINK_SUBTLE_STATEFUL_HMAC_BORINGSSL_H_

#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// A BoringSSL HMAC implementation of Stateful Mac interface.
class StatefulHmacBoringSsl : public subtle::StatefulMac {
 public:
  static util::StatusOr<std::unique_ptr<StatefulMac>> New(
      HashType hash_type, uint32_t tag_size, const util::SecretData& key_value);
  util::Status Update(absl::string_view data) override;
  util::StatusOr<std::string> Finalize() override;

 private:
  // Minimum HMAC key size in bytes.
  static constexpr size_t kMinKeySize = 16;

  StatefulHmacBoringSsl(uint32_t tag_size, internal::SslUniquePtr<HMAC_CTX> ctx)
      : hmac_context_(std::move(ctx)), tag_size_(tag_size) {}

  const internal::SslUniquePtr<HMAC_CTX> hmac_context_;
  const uint32_t tag_size_;
};

class StatefulHmacBoringSslFactory : public subtle::StatefulMacFactory {
 public:
  StatefulHmacBoringSslFactory(HashType hash_type, uint32_t tag_size,
                               const util::SecretData& key_value);
  util::StatusOr<std::unique_ptr<StatefulMac>> Create() const override;

 private:
  const HashType hash_type_;
  const uint32_t tag_size_;
  const util::SecretData key_value_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STATEFUL_HMAC_BORINGSSL_H_
