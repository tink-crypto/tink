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

#ifndef TINK_SUBTLE_STATEFUL_CMAC_BORINGSSL_H_
#define TINK_SUBTLE_STATEFUL_CMAC_BORINGSSL_H_

#include <memory>
#include <utility>

#include "openssl/base.h"
#include "openssl/cmac.h"
#include "openssl/evp.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// A BoringSSL CMAC implementation of Stateful Mac interface.
class StatefulCmacBoringSsl : public subtle::StatefulMac {
 public:
  // Key must be 16 or 32 bytes, all other sizes will be rejected.
  static util::StatusOr<std::unique_ptr<StatefulMac>> New(
      uint32_t tag_size, const util::SecretData& key_value);
  util::Status Update(absl::string_view data) override;
  util::StatusOr<std::string> Finalize() override;

 private:
  static constexpr size_t kSmallKeySize = 16;
  static constexpr size_t kBigKeySize = 32;
  static constexpr size_t kMaxTagSize = 16;

  StatefulCmacBoringSsl(uint32_t tag_size, bssl::UniquePtr<CMAC_CTX> ctx)
      : cmac_context_(std::move(ctx)), tag_size_(tag_size) {}

  const bssl::UniquePtr<CMAC_CTX> cmac_context_;
  const uint32_t tag_size_;
};

class StatefulCmacBoringSslFactory : public subtle::StatefulMacFactory {
 public:
  StatefulCmacBoringSslFactory(uint32_t tag_size,
                               const util::SecretData& key_value);
  util::StatusOr<std::unique_ptr<StatefulMac>> Create() const override;

 private:
  const uint32_t tag_size_;
  const util::SecretData key_value_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STATEFUL_CMAC_BORINGSSL_H_
